"""
BRAMKA AI - Nmap Wrapper
Professional network reconnaissance and port scanning
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import subprocess

from src.utils.logger import get_logger
from src.utils.config_loader import get_config


class ScanType(Enum):
    """Available scan types"""
    QUICK = "quick"           # Fast scan, common ports
    STEALTH = "stealth"       # SYN scan, slower but stealthy
    AGGRESSIVE = "aggressive" # Comprehensive scan with OS detection
    CUSTOM = "custom"         # Custom arguments


@dataclass
class ScanResult:
    """Structured scan result"""
    target: str
    scan_type: str
    open_ports: List[Dict[str, Any]]
    os_detection: Optional[str]
    scan_duration: float
    success: bool
    raw_output: str
    error: Optional[str] = None


class NmapWrapper:
    """
    Professional Nmap wrapper for network reconnaissance
    
    Features:
    - Multiple scan modes (quick, stealth, aggressive)
    - Port and service detection
    - OS fingerprinting
    - Async execution
    - Result parsing
    """
    
    def __init__(self):
        self.logger = get_logger("NmapWrapper")
        self.config = get_config()
        
        # Get Nmap config
        nmap_config = self.config.get('attack_orchestrator.reconnaissance.nmap', {})
        self.default_args = nmap_config.get('default_args', '-sV -T4')
        self.aggressive_args = nmap_config.get('aggressive_args', '-A -T4')
        self.stealth_args = nmap_config.get('stealth_args', '-sS -T2')
        self.timeout = nmap_config.get('timeout', 300)
        
        # Verify Nmap installation
        self._verify_nmap()
        
        self.logger.info("✅ Nmap wrapper initialized")
    
    def _verify_nmap(self):
        """Verify Nmap is installed"""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.split('\n')[0]
                self.logger.info(f"Nmap found: {version}")
            else:
                raise RuntimeError("Nmap not found")
        except Exception as e:
            self.logger.error(f"❌ Nmap verification failed: {e}")
            raise RuntimeError("Nmap is not installed or not in PATH")
    
    def _sanitize_target(self, target: str) -> str:
        """
        Sanitize target to prevent command injection
        
        Args:
            target: IP address, domain, or CIDR
        
        Returns:
            Sanitized target
        
        Raises:
            ValueError: If target format is invalid
        """
        # Remove any dangerous characters
        dangerous_chars = [';', '&', '|', '$', '`', '\n', '\r']
        for char in dangerous_chars:
            if char in target:
                raise ValueError(f"Invalid character in target: {char}")
        
        # Validate format (IP, domain, or CIDR)
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-_.]+[a-zA-Z0-9]$'
        
        if not (re.match(ip_pattern, target) or re.match(domain_pattern, target)):
            raise ValueError(f"Invalid target format: {target}")
        
        return target
    
    def _build_command(
        self,
        target: str,
        scan_type: ScanType,
        ports: Optional[str] = None,
        custom_args: Optional[str] = None
    ) -> List[str]:
        """
        Build Nmap command
        
        Args:
            target: Sanitized target
            scan_type: Type of scan
            ports: Port specification (e.g., "80,443" or "1-1000")
            custom_args: Custom Nmap arguments
        
        Returns:
            Command as list of arguments
        """
        cmd = ['nmap']
        
        # Add scan type arguments
        if scan_type == ScanType.QUICK:
            cmd.extend(self.default_args.split())
        elif scan_type == ScanType.STEALTH:
            cmd.extend(self.stealth_args.split())
        elif scan_type == ScanType.AGGRESSIVE:
            cmd.extend(self.aggressive_args.split())
        elif scan_type == ScanType.CUSTOM and custom_args:
            cmd.extend(custom_args.split())
        
        # Add port specification
        if ports:
            cmd.extend(['-p', ports])
        
        # Output in XML format for easier parsing
        cmd.extend(['-oX', '-'])
        
        # Add target
        cmd.append(target)
        
        return cmd
    
    async def scan(
        self,
        target: str,
        scan_type: ScanType = ScanType.QUICK,
        ports: Optional[str] = None,
        custom_args: Optional[str] = None
    ) -> ScanResult:
        """
        Perform network scan
        
        Args:
            target: IP address, domain, or CIDR range
            scan_type: Type of scan to perform
            ports: Port specification (optional)
            custom_args: Custom Nmap arguments (optional)
        
        Returns:
            ScanResult object with findings
        """
        import time
        
        self.logger.info(f"🔍 Starting {scan_type.value} scan on {target}")
        
        try:
            # Sanitize target
            safe_target = self._sanitize_target(target)
            
            # Build command
            cmd = self._build_command(safe_target, scan_type, ports, custom_args)
            
            self.logger.debug(f"Command: {' '.join(cmd)}")
            
            # Execute scan
            start_time = time.time()
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise TimeoutError(f"Scan timeout after {self.timeout}s")
            
            duration = time.time() - start_time
            
            if process.returncode != 0:
                error_msg = stderr.decode()
                self.logger.error(f"❌ Scan failed: {error_msg}")
                return ScanResult(
                    target=safe_target,
                    scan_type=scan_type.value,
                    open_ports=[],
                    os_detection=None,
                    scan_duration=duration,
                    success=False,
                    raw_output=error_msg,
                    error=error_msg
                )
            
            # Parse results
            raw_output = stdout.decode()
            parsed = self._parse_xml_output(raw_output)
            
            self.logger.info(
                f"✅ Scan complete: {len(parsed['open_ports'])} ports found in {duration:.2f}s"
            )
            
            return ScanResult(
                target=safe_target,
                scan_type=scan_type.value,
                open_ports=parsed['open_ports'],
                os_detection=parsed.get('os_detection'),
                scan_duration=duration,
                success=True,
                raw_output=raw_output
            )
            
        except ValueError as e:
            self.logger.error(f"❌ Invalid target: {e}")
            return ScanResult(
                target=target,
                scan_type=scan_type.value,
                open_ports=[],
                os_detection=None,
                scan_duration=0,
                success=False,
                raw_output="",
                error=str(e)
            )
        except Exception as e:
            self.logger.error(f"❌ Scan error: {e}", exc_info=True)
            return ScanResult(
                target=target,
                scan_type=scan_type.value,
                open_ports=[],
                os_detection=None,
                scan_duration=0,
                success=False,
                raw_output="",
                error=str(e)
            )
    
    def _parse_xml_output(self, xml_output: str) -> Dict[str, Any]:
        """
        Parse Nmap XML output
        
        Args:
            xml_output: Raw XML output from Nmap
        
        Returns:
            Dictionary with parsed results
        """
        import xml.etree.ElementTree as ET
        
        try:
            root = ET.fromstring(xml_output)
            
            open_ports = []
            os_detection = None
            
            # Parse hosts
            for host in root.findall('.//host'):
                # Parse ports
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        service = port.find('service')
                        
                        port_info = {
                            'port': int(port.get('portid')),
                            'protocol': port.get('protocol'),
                            'state': 'open',
                            'service': service.get('name') if service is not None else 'unknown',
                            'version': service.get('version') if service is not None else None,
                            'product': service.get('product') if service is not None else None
                        }
                        
                        open_ports.append(port_info)
                
                # Parse OS detection
                os_elem = host.find('.//osmatch')
                if os_elem is not None:
                    os_detection = os_elem.get('name')
            
            return {
                'open_ports': open_ports,
                'os_detection': os_detection
            }
            
        except Exception as e:
            self.logger.warning(f"⚠️ XML parsing failed: {e}")
            return {
                'open_ports': [],
                'os_detection': None
            }
    
    async def quick_scan(self, target: str) -> ScanResult:
        """Quick scan of common ports"""
        return await self.scan(target, ScanType.QUICK)
    
    async def stealth_scan(self, target: str) -> ScanResult:
        """Stealthy SYN scan"""
        return await self.scan(target, ScanType.STEALTH)
    
    async def aggressive_scan(self, target: str) -> ScanResult:
        """Comprehensive scan with OS detection"""
        return await self.scan(target, ScanType.AGGRESSIVE)
    
    def format_results(self, result: ScanResult) -> str:
        """
        Format scan results for display
        
        Args:
            result: ScanResult object
        
        Returns:
            Formatted string
        """
        if not result.success:
            return f"❌ Scan failed: {result.error}"
        
        output = [
            f"🎯 Scan Results for {result.target}",
            f"   Type: {result.scan_type}",
            f"   Duration: {result.scan_duration:.2f}s",
            f"   Open Ports: {len(result.open_ports)}",
            ""
        ]
        
        if result.os_detection:
            output.append(f"   OS Detection: {result.os_detection}\n")
        
        if result.open_ports:
            output.append("   Port Details:")
            for port in result.open_ports:
                service_info = f"{port['service']}"
                if port['version']:
                    service_info += f" {port['version']}"
                output.append(
                    f"      • {port['port']}/{port['protocol']} - {service_info}"
                )
        else:
            output.append("   No open ports found")
        
        return '\n'.join(output)


# Testing
async def test_nmap():
    """Test Nmap wrapper"""
    from src.utils.logger import setup_logger
    
    setup_logger(log_level="INFO")
    
    nmap = NmapWrapper()
    
    # Test quick scan on localhost
    print("\n" + "="*60)
    print("Testing Quick Scan on localhost")
    print("="*60)
    
    result = await nmap.quick_scan("127.0.0.1")
    print(nmap.format_results(result))
    
    print("\n" + "="*60)
    print("Test Complete")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(test_nmap())
