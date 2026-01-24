"""
BRAMKA AI - SQLmap Wrapper
Professional SQL injection detection and exploitation
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


class InjectionType(Enum):
    """SQL injection types"""
    BOOLEAN_BASED = "boolean-based blind"
    TIME_BASED = "time-based blind"
    ERROR_BASED = "error-based"
    UNION_QUERY = "UNION query"
    STACKED_QUERIES = "stacked queries"


@dataclass
class SQLMapResult:
    """SQLmap scan result"""
    target_url: str
    vulnerable: bool
    injection_type: Optional[str]
    database_type: Optional[str]
    databases: List[str]
    tables: List[str]
    data_extracted: Dict[str, Any]
    scan_duration: float
    success: bool
    raw_output: str
    error: Optional[str] = None


class SQLMapWrapper:
    """
    Professional SQLmap wrapper for SQL injection testing
    
    Features:
    - Automatic SQL injection detection
    - Database enumeration
    - Data extraction
    - Multiple injection techniques
    - Safe operation with timeouts
    """
    
    def __init__(self):
        self.logger = get_logger("SQLMapWrapper")
        self.config = get_config()
        
        # Get SQLmap config
        sqlmap_config = self.config.get('attack_orchestrator.exploitation.sqlmap', {})
        self.default_args = sqlmap_config.get('default_args', '--batch --random-agent')
        self.timeout = sqlmap_config.get('timeout', 600)
        self.risk = sqlmap_config.get('risk', 1)
        self.level = sqlmap_config.get('level', 1)
        
        # Session directory
        self.session_dir = Path("data/downloads/sqlmap_sessions")
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # Verify SQLmap installation
        self._verify_sqlmap()
        
        self.logger.info("✅ SQLmap wrapper initialized")
    
    def _verify_sqlmap(self):
        """Verify SQLmap is installed"""
        try:
            result = subprocess.run(
                ['sqlmap', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                self.logger.info(f"SQLmap found: {version}")
            else:
                raise RuntimeError("SQLmap not found")
        except Exception as e:
            self.logger.error(f"❌ SQLmap verification failed: {e}")
            raise RuntimeError("SQLmap is not installed or not in PATH")
    
    def _sanitize_url(self, url: str) -> str:
        """
        Sanitize URL to prevent issues
        
        Args:
            url: Target URL
        
        Returns:
            Sanitized URL
        
        Raises:
            ValueError: If URL is invalid
        """
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        
        # Check for dangerous patterns
        dangerous_patterns = [';', '&', '|', '$', '`', '\n', '\r']
        for pattern in dangerous_patterns:
            if pattern in url.split('?')[0]:  # Only check base URL, params are ok
                raise ValueError(f"Invalid character in URL: {pattern}")
        
        return url
    
    def _build_command(
        self,
        url: str,
        test_parameter: Optional[str] = None,
        custom_args: Optional[List[str]] = None
    ) -> List[str]:
        """
        Build SQLmap command
        
        Args:
            url: Target URL
            test_parameter: Specific parameter to test
            custom_args: Custom arguments
        
        Returns:
            Command list
        """
        cmd = ['sqlmap', '-u', url]
        
        # Add default arguments
        cmd.extend(self.default_args.split())
        
        # Risk and level
        cmd.extend(['--risk', str(self.risk)])
        cmd.extend(['--level', str(self.level)])
        
        # Specific parameter
        if test_parameter:
            cmd.extend(['-p', test_parameter])
        
        # Session file
        session_file = self.session_dir / f"session_{hash(url)}.sqlite"
        cmd.extend(['-s', str(session_file)])
        
        # Custom arguments
        if custom_args:
            cmd.extend(custom_args)
        
        return cmd
    
    async def test_injection(
        self,
        url: str,
        parameter: Optional[str] = None,
        custom_args: Optional[List[str]] = None
    ) -> SQLMapResult:
        """
        Test for SQL injection vulnerability
        
        Args:
            url: Target URL with parameters
            parameter: Specific parameter to test (optional)
            custom_args: Custom SQLmap arguments (optional)
        
        Returns:
            SQLMapResult object
        """
        import time
        
        self.logger.info(f"🔍 Testing SQL injection on {url}")
        
        try:
            # Sanitize URL
            safe_url = self._sanitize_url(url)
            
            # Build command
            cmd = self._build_command(safe_url, parameter, custom_args)
            
            self.logger.debug(f"Command: {' '.join(cmd)}")
            
            # Execute test
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
                raise TimeoutError(f"Test timeout after {self.timeout}s")
            
            duration = time.time() - start_time
            raw_output = stdout.decode()
            
            # Parse results
            parsed = self._parse_output(raw_output)
            
            if parsed['vulnerable']:
                self.logger.warning(
                    f"⚠️ VULNERABLE! {parsed['injection_type']} on {parsed.get('parameter', 'unknown')}"
                )
            else:
                self.logger.info("✅ No SQL injection found")
            
            return SQLMapResult(
                target_url=safe_url,
                vulnerable=parsed['vulnerable'],
                injection_type=parsed.get('injection_type'),
                database_type=parsed.get('database_type'),
                databases=[],
                tables=[],
                data_extracted={},
                scan_duration=duration,
                success=True,
                raw_output=raw_output
            )
            
        except ValueError as e:
            self.logger.error(f"❌ Invalid URL: {e}")
            return SQLMapResult(
                target_url=url,
                vulnerable=False,
                injection_type=None,
                database_type=None,
                databases=[],
                tables=[],
                data_extracted={},
                scan_duration=0,
                success=False,
                raw_output="",
                error=str(e)
            )
        except Exception as e:
            self.logger.error(f"❌ Test error: {e}", exc_info=True)
            return SQLMapResult(
                target_url=url,
                vulnerable=False,
                injection_type=None,
                database_type=None,
                databases=[],
                tables=[],
                data_extracted={},
                scan_duration=0,
                success=False,
                raw_output="",
                error=str(e)
            )
    
    def _parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse SQLmap output
        
        Args:
            output: Raw SQLmap output
        
        Returns:
            Parsed results dictionary
        """
        result = {
            'vulnerable': False,
            'injection_type': None,
            'database_type': None,
            'parameter': None
        }
        
        # Check for vulnerability
        if 'is vulnerable' in output.lower() or 'parameter appears to be' in output.lower():
            result['vulnerable'] = True
        
        # Extract injection type
        for line in output.split('\n'):
            if 'Type:' in line:
                # Extract injection type
                for inj_type in InjectionType:
                    if inj_type.value.lower() in line.lower():
                        result['injection_type'] = inj_type.value
                        break
            
            # Extract database type
            if 'back-end DBMS:' in line:
                # Extract database name
                db_match = re.search(r'back-end DBMS:\s*(\w+)', line)
                if db_match:
                    result['database_type'] = db_match.group(1)
            
            # Extract vulnerable parameter
            if 'Parameter:' in line:
                param_match = re.search(r'Parameter:\s*(\w+)', line)
                if param_match:
                    result['parameter'] = param_match.group(1)
        
        return result
    
    async def enumerate_databases(self, url: str) -> SQLMapResult:
        """
        Enumerate databases (if vulnerable)
        
        Args:
            url: Vulnerable URL
        
        Returns:
            SQLMapResult with database list
        """
        self.logger.info(f"📊 Enumerating databases on {url}")
        
        try:
            safe_url = self._sanitize_url(url)
            
            # Build command with --dbs flag
            cmd = self._build_command(safe_url, custom_args=['--dbs'])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            raw_output = stdout.decode()
            databases = self._extract_databases(raw_output)
            
            self.logger.info(f"✅ Found {len(databases)} databases")
            
            return SQLMapResult(
                target_url=safe_url,
                vulnerable=True,
                injection_type=None,
                database_type=None,
                databases=databases,
                tables=[],
                data_extracted={},
                scan_duration=0,
                success=True,
                raw_output=raw_output
            )
            
        except Exception as e:
            self.logger.error(f"❌ Enumeration error: {e}")
            return SQLMapResult(
                target_url=url,
                vulnerable=False,
                injection_type=None,
                database_type=None,
                databases=[],
                tables=[],
                data_extracted={},
                scan_duration=0,
                success=False,
                raw_output="",
                error=str(e)
            )
    
    def _extract_databases(self, output: str) -> List[str]:
        """Extract database names from output"""
        databases = []
        in_db_section = False
        
        for line in output.split('\n'):
            if 'available databases' in line.lower():
                in_db_section = True
                continue
            
            if in_db_section:
                # Database lines start with [*]
                if line.strip().startswith('[*]'):
                    db_name = line.strip()[3:].strip()
                    if db_name:
                        databases.append(db_name)
                elif line.strip() == '':
                    in_db_section = False
        
        return databases
    
    def format_results(self, result: SQLMapResult) -> str:
        """
        Format SQLmap results for display
        
        Args:
            result: SQLMapResult object
        
        Returns:
            Formatted string
        """
        if not result.success:
            return f"❌ Test failed: {result.error}"
        
        output = [
            f"🎯 SQL Injection Test Results for {result.target_url}",
            f"   Duration: {result.scan_duration:.2f}s",
            ""
        ]
        
        if result.vulnerable:
            output.append("   ⚠️ VULNERABLE TO SQL INJECTION")
            if result.injection_type:
                output.append(f"   Injection Type: {result.injection_type}")
            if result.database_type:
                output.append(f"   Database: {result.database_type}")
        else:
            output.append("   ✅ Not vulnerable")
        
        if result.databases:
            output.append(f"\n   Databases Found: {len(result.databases)}")
            for db in result.databases[:5]:  # Show first 5
                output.append(f"      • {db}")
            if len(result.databases) > 5:
                output.append(f"      ... and {len(result.databases) - 5} more")
        
        return '\n'.join(output)


# Testing
async def test_sqlmap():
    """Test SQLmap wrapper"""
    from src.utils.logger import setup_logger
    
    setup_logger(log_level="INFO")
    
    sqlmap = SQLMapWrapper()
    
    # Test on a safe test URL (intentionally vulnerable test site)
    # NOTE: Replace with actual test URL or skip for now
    print("\n" + "="*60)
    print("SQLmap Wrapper Ready")
    print("="*60)
    print("\n⚠️  Note: Real SQL injection testing requires a vulnerable target")
    print("Use only on authorized test systems!")
    print("\nWrapper initialized successfully ✅")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(test_sqlmap())
