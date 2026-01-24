"""
BRAMKA AI - Hydra Wrapper
Fast network login brute-forcer
"""

import asyncio
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path

from src.utils.logger import get_logger
from src.utils.config_loader import get_config


@dataclass
class BruteForceResult:
    """Hydra brute-force result"""
    target: str
    service: str
    success: bool
    credentials_found: List[Dict[str, str]]
    attempts: int
    duration: float
    output: str
    error: Optional[str] = None


class HydraWrapper:
    """
    Hydra password brute-force wrapper
    
    Supported services:
    - SSH, FTP, HTTP, HTTPS, SMB, RDP, MySQL, PostgreSQL, etc.
    
    Features:
    - Single/multiple username testing
    - Wordlist-based attacks
    - Custom password lists
    - Multiple protocol support
    """
    
    def __init__(self):
        self.logger = get_logger("HydraWrapper")
        self.config = get_config()
        
        self.hydra_cmd = "hydra"
        self.default_wordlist = "/usr/share/wordlists/rockyou.txt"
        
        self._verify_hydra()
        
        self.logger.info("✅ Hydra wrapper initialized")
    
    def _verify_hydra(self):
        """Verify Hydra is installed"""
        try:
            result = subprocess.run(
                ['hydra', '-h'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 or "Hydra" in result.stdout:
                self.logger.info("Hydra found")
            else:
                raise RuntimeError("Hydra not found")
        except Exception as e:
            self.logger.error(f"❌ Hydra verification failed: {e}")
            raise RuntimeError("Hydra is not installed")
    
    async def brute_force(
        self,
        target: str,
        service: str,
        username: Optional[str] = None,
        userlist: Optional[str] = None,
        password: Optional[str] = None,
        passlist: Optional[str] = None,
        port: Optional[int] = None,
        threads: int = 4
    ) -> BruteForceResult:
        """
        Perform brute-force attack
        
        Args:
            target: Target IP/hostname
            service: Service to attack (ssh, ftp, http-get, etc.)
            username: Single username
            userlist: Path to username list
            password: Single password
            passlist: Path to password list
            port: Custom port
            threads: Number of parallel threads
        
        Returns:
            BruteForceResult object
        """
        import time
        import subprocess
        
        self.logger.info(f"🔓 Brute-forcing {service} on {target}")
        
        # Build command
        cmd = [self.hydra_cmd, '-t', str(threads)]
        
        # Username
        if username:
            cmd.extend(['-l', username])
        elif userlist:
            cmd.extend(['-L', userlist])
        else:
            self.logger.error("No username or userlist provided")
            return BruteForceResult(
                target=target,
                service=service,
                success=False,
                credentials_found=[],
                attempts=0,
                duration=0,
                output="",
                error="No username specified"
            )
        
        # Password
        if password:
            cmd.extend(['-p', password])
        elif passlist:
            cmd.extend(['-P', passlist])
        else:
            # Use default wordlist if exists
            if Path(self.default_wordlist).exists():
                cmd.extend(['-P', self.default_wordlist])
                self.logger.info(f"Using default wordlist: {self.default_wordlist}")
            else:
                return BruteForceResult(
                    target=target,
                    service=service,
                    success=False,
                    credentials_found=[],
                    attempts=0,
                    duration=0,
                    output="",
                    error="No password list specified"
                )
        
        # Port
        if port:
            cmd.extend(['-s', str(port)])
        
        # Target and service
        cmd.append(target)
        cmd.append(service)
        
        # Verbose output
        cmd.append('-V')
        
        self.logger.debug(f"Command: {' '.join(cmd)}")
        
        try:
            start = time.time()
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300  # 5 min timeout
            )
            
            duration = time.time() - start
            output = stdout.decode()
            
            # Parse results
            credentials = self._parse_credentials(output)
            attempts = self._count_attempts(output)
            
            success = len(credentials) > 0
            
            if success:
                self.logger.info(f"✅ Found {len(credentials)} valid credentials!")
            else:
                self.logger.info("⚠️ No credentials found")
            
            return BruteForceResult(
                target=target,
                service=service,
                success=success,
                credentials_found=credentials,
                attempts=attempts,
                duration=duration,
                output=output
            )
            
        except asyncio.TimeoutError:
            self.logger.warning("⏱️ Brute-force timeout")
            return BruteForceResult(
                target=target,
                service=service,
                success=False,
                credentials_found=[],
                attempts=0,
                duration=0,
                output="",
                error="Timeout"
            )
        except Exception as e:
            self.logger.error(f"❌ Brute-force error: {e}")
            return BruteForceResult(
                target=target,
                service=service,
                success=False,
                credentials_found=[],
                attempts=0,
                duration=0,
                output="",
                error=str(e)
            )
    
    def _parse_credentials(self, output: str) -> List[Dict[str, str]]:
        """Parse found credentials from output"""
        credentials = []
        
        # Pattern: [22][ssh] host: 192.168.1.1   login: admin   password: password123
        pattern = r'\[.*?\]\[.*?\].*?login:\s*(\S+)\s+password:\s*(\S+)'
        
        for match in re.finditer(pattern, output):
            credentials.append({
                'username': match.group(1),
                'password': match.group(2)
            })
        
        return credentials
    
    def _count_attempts(self, output: str) -> int:
        """Count number of attempts from output"""
        # Count lines with "attempt" or credential tries
        return output.count('[ATTEMPT]')
    
    async def ssh_brute_force(
        self,
        target: str,
        username: str,
        passlist: Optional[str] = None,
        port: int = 22
    ) -> BruteForceResult:
        """SSH brute-force shortcut"""
        return await self.brute_force(
            target=target,
            service="ssh",
            username=username,
            passlist=passlist,
            port=port
        )
    
    async def ftp_brute_force(
        self,
        target: str,
        username: str = "anonymous",
        passlist: Optional[str] = None,
        port: int = 21
    ) -> BruteForceResult:
        """FTP brute-force shortcut"""
        return await self.brute_force(
            target=target,
            service="ftp",
            username=username,
            passlist=passlist,
            port=port
        )
    
    async def http_brute_force(
        self,
        target: str,
        username: str,
        passlist: Optional[str] = None,
        method: str = "http-get"
    ) -> BruteForceResult:
        """HTTP brute-force shortcut"""
        return await self.brute_force(
            target=target,
            service=method,
            username=username,
            passlist=passlist
        )
    
    def format_results(self, result: BruteForceResult) -> str:
        """Format results for display"""
        if not result.success:
            return f"❌ Attack failed: {result.error or 'No credentials found'}"
        
        output = [
            f"🎯 Brute-Force Results for {result.target}",
            f"   Service: {result.service}",
            f"   Duration: {result.duration:.2f}s",
            f"   Attempts: {result.attempts}",
            f"   Credentials Found: {len(result.credentials_found)}",
            ""
        ]
        
        if result.credentials_found:
            output.append("   Valid Credentials:")
            for cred in result.credentials_found:
                output.append(f"      • {cred['username']}:{cred['password']}")
        
        return '\n'.join(output)


# Testing
async def test_hydra():
    """Test Hydra wrapper"""
    from src.utils.logger import setup_logger
    import subprocess
    
    setup_logger(log_level="INFO")
    
    hydra = HydraWrapper()
    
    print("\n" + "="*60)
    print("Hydra Wrapper Ready")
    print("="*60)
    print("\n⚠️  Note: Real brute-force testing requires:")
    print("   - Valid target with permission")
    print("   - Username/password lists")
    print("\nWrapper initialized successfully ✅")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(test_hydra())
