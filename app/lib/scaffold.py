#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         HUBTEL RECON - POC SCAFFOLD                           ║
║                      Security POC Generation Toolkit                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Organization : GAZE Limited                                                 ║
║  Team         : Security Operations                                            ║
║  Purpose      : Generate POC scripts from templates for security testing       ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Usage:
    # Interactive mode
    python scaffold.py new my_poc
    
    # With arguments
    python scaffold.py new idor_test --template idor --target api.hubtel.com
    
    # From library
    from app.lib.scaffold import POCScaffold
    scaffold = POCScaffold()
    scaffold.generate("my_poc", template="auth", target="api.hubtel.com")

Templates:
    - default: Standard enumeration POC
    - auth: Authentication testing
    - idor: IDOR/BOLA testing
    - injection: Injection payload testing
    - rate_limit: Rate limiting tests
    - file_upload: File upload testing
"""
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict
from dataclasses import dataclass
from textwrap import dedent


# ══════════════════════════════════════════════════════════════════════════════
# Colors
# ══════════════════════════════════════════════════════════════════════════════

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


BANNER = f"""
{Colors.CYAN}{Colors.BOLD}
    ██████╗  ██████╗  ██████╗    ███████╗ ██████╗ █████╗ ███████╗███████╗ ██████╗ ██╗     ██████╗ 
    ██╔══██╗██╔═══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██║     ██╔══██╗
    ██████╔╝██║   ██║██║         ███████╗██║     ███████║█████╗  █████╗  ██║   ██║██║     ██║  ██║
    ██╔═══╝ ██║   ██║██║         ╚════██║██║     ██╔══██║██╔══╝  ██╔══╝  ██║   ██║██║     ██║  ██║
    ██║     ╚██████╔╝╚██████╗    ███████║╚██████╗██║  ██║██║     ██║     ╚██████╔╝███████╗██████╔╝
    ╚═╝      ╚═════╝  ╚═════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝      ╚═════╝ ╚══════╝╚═════╝ 
{Colors.RESET}
{Colors.DIM}    GAZE Security - POC Generator{Colors.RESET}
"""


# ══════════════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class POCConfig:
    """POC configuration data"""
    name: str
    author: str = "Security Team"
    email: str = "security@hubtel.com"
    target: str = "api.hubtel.com"
    endpoint: str = "/api/v1/endpoint"
    method: str = "GET"
    description: str = "Security validation POC"
    template: str = "default"
    output_dir: str = "./pocs"


# ══════════════════════════════════════════════════════════════════════════════
# Templates
# ══════════════════════════════════════════════════════════════════════════════

TEMPLATES = {
    "default": '''#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║  POC: {name}
║  Target: {target}
║  Author: {author} <{email}>
║  Date: {date}
║  Description: {description}
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import asyncio
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent.parent))

from app.lib.recon import GAZERecon, Validators, ReconResponse


# ══════════════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════════════

CONFIG = {{
    "target": "{target}",
    "endpoint": "{endpoint}",
    "method": "{method}",
    "token": None,  # Add your token here
    "headers": {{
        # "X-Custom-Header": "value",
    }},
}}


# ══════════════════════════════════════════════════════════════════════════════
# Custom Validators
# ══════════════════════════════════════════════════════════════════════════════

def custom_validator(response: ReconResponse) -> bool:
    """
    Define your validation logic here.
    Return True if the response indicates a successful finding.
    """
    # Example: Check for specific data exposure
    if response.status == 200:
        data = response.json()
        if data and "user" in data:
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# Main POC Logic
# ══════════════════════════════════════════════════════════════════════════════

async def run_poc():
    """Execute the POC"""
    print(f"[*] Target: {{CONFIG['target']}}")
    print(f"[*] Endpoint: {{CONFIG['endpoint']}}")
    
    async with GAZERecon(
        token=CONFIG["token"],
        headers=CONFIG["headers"],
        verbose=True,
    ) as recon:
        
        # Single request test
        url = f"https://{{CONFIG['target']}}{{CONFIG['endpoint']}}"
        response = await recon.get(url)
        
        print(f"[+] Status: {{response.status}}")
        print(f"[+] Body Length: {{response.body_length}}")
        
        if custom_validator(response):
            print("[!] VULNERABILITY CONFIRMED")
            return True
        else:
            print("[-] No vulnerability detected")
            return False


if __name__ == "__main__":
    try:
        result = asyncio.run(run_poc())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\\n[!] Interrupted")
        sys.exit(130)
''',

    "idor": '''#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║  POC: {name} - IDOR/BOLA Testing
║  Target: {target}
║  Author: {author} <{email}>
║  Date: {date}
║  Description: {description}
║  
║  IDOR (Insecure Direct Object Reference) testing POC
║  Tests access control on resource identifiers
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import asyncio
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent.parent))

from app.lib.recon import GAZERecon, Validators, ReconResponse


# ══════════════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════════════

CONFIG = {{
    "target": "{target}",
    "endpoint": "{endpoint}",  # Use {{n}} for ID placeholder
    "method": "{method}",
    
    # Tokens for different users
    "attacker_token": None,  # Low-privilege user token
    "victim_id": "12345",     # Target resource ID
    
    # Enumeration settings
    "id_start": 1,
    "id_end": 100,
    "concurrency": 10,
    
    "headers": {{}},
}}


# ══════════════════════════════════════════════════════════════════════════════
# Validators
# ══════════════════════════════════════════════════════════════════════════════

def idor_validator(response: ReconResponse) -> bool:
    """Check if we can access another user's resource"""
    if response.status == 200:
        data = response.json()
        if data:
            # Check for sensitive fields that indicate data access
            sensitive_fields = ["email", "phone", "address", "balance", "password"]
            for field in sensitive_fields:
                if field in str(data).lower():
                    return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# POC Logic
# ══════════════════════════════════════════════════════════════════════════════

async def test_single_id():
    """Test access to a specific ID"""
    print(f"[*] Testing single ID access: {{CONFIG['victim_id']}}")
    
    async with GAZERecon(
        token=CONFIG["attacker_token"],
        headers=CONFIG["headers"],
        verbose=True,
    ) as recon:
        url = f"https://{{CONFIG['target']}}{{CONFIG['endpoint']}}".replace("{{n}}", CONFIG["victim_id"])
        response = await recon.get(url)
        
        if idor_validator(response):
            print(f"[!] IDOR CONFIRMED - Can access ID: {{CONFIG['victim_id']}}")
            print(f"[!] Response: {{response.body[:500]}}")
            return True
        else:
            print(f"[-] Access denied for ID: {{CONFIG['victim_id']}}")
            return False


async def enumerate_ids():
    """Enumerate IDs to find accessible resources"""
    print(f"[*] Enumerating IDs: {{CONFIG['id_start']}} - {{CONFIG['id_end']}}")
    
    async with GAZERecon(
        token=CONFIG["attacker_token"],
        headers=CONFIG["headers"],
        verbose=True,
    ) as recon:
        hits = await recon.enumerate_range(
            url_template=f"https://{{CONFIG['target']}}{{CONFIG['endpoint']}}",
            start=CONFIG["id_start"],
            end=CONFIG["id_end"],
            validators=[idor_validator],
            concurrency=CONFIG["concurrency"],
        )
        
        if hits:
            print(f"\\n[!] IDOR FOUND - {{len(hits)}} accessible resources")
            for hit in hits:
                print(f"    - ID: {{hit.marker}}")
            return True
        else:
            print("[-] No IDOR vulnerabilities found")
            return False


async def run_poc():
    """Execute the IDOR POC"""
    # Test 1: Single ID access
    single_result = await test_single_id()
    
    # Test 2: Enumerate IDs
    enum_result = await enumerate_ids()
    
    return single_result or enum_result


if __name__ == "__main__":
    try:
        result = asyncio.run(run_poc())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\\n[!] Interrupted")
        sys.exit(130)
''',

    "auth": '''#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║  POC: {name} - Authentication Testing
║  Target: {target}
║  Author: {author} <{email}>
║  Date: {date}
║  Description: {description}
║  
║  Authentication bypass and credential testing POC
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import asyncio
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent.parent))

from app.lib.recon import GAZERecon, Validators, ReconResponse


# ══════════════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════════════

CONFIG = {{
    "target": "{target}",
    "login_endpoint": "/api/v1/auth/login",
    "protected_endpoint": "{endpoint}",
    
    # Test credentials
    "test_users": [
        {{"email": "test@test.com", "password": "password123"}},
        {{"email": "admin@hubtel.com", "password": "admin"}},
    ],
    
    # Bypass tests
    "bypass_headers": [
        {{"X-Forwarded-For": "127.0.0.1"}},
        {{"X-Real-IP": "127.0.0.1"}},
        {{"X-Original-URL": "/admin"}},
    ],
    
    "headers": {{}},
}}


# ══════════════════════════════════════════════════════════════════════════════
# Tests
# ══════════════════════════════════════════════════════════════════════════════

async def test_auth_bypass():
    """Test authentication bypass techniques"""
    print("[*] Testing authentication bypass...")
    
    async with GAZERecon(verbose=True) as recon:
        base_url = f"https://{{CONFIG['target']}}{{CONFIG['protected_endpoint']}}"
        
        # Test without auth
        response = await recon.get(base_url)
        if response.status == 200:
            print("[!] BYPASS: Endpoint accessible without authentication!")
            return True
        
        # Test with bypass headers
        for bypass_header in CONFIG["bypass_headers"]:
            recon.custom_headers = bypass_header
            response = await recon.get(base_url)
            if response.status == 200:
                print(f"[!] BYPASS: Works with header {{bypass_header}}")
                return True
        
        print("[-] No authentication bypass found")
        return False


async def test_default_credentials():
    """Test for default/weak credentials"""
    print("[*] Testing default credentials...")
    
    async with GAZERecon(verbose=True) as recon:
        login_url = f"https://{{CONFIG['target']}}{{CONFIG['login_endpoint']}}"
        
        for creds in CONFIG["test_users"]:
            response = await recon.post(login_url, creds)
            
            if response.status == 200:
                data = response.json()
                if data and ("token" in data or "access_token" in data):
                    print(f"[!] VALID CREDENTIALS: {{creds['email']}}")
                    return True
        
        print("[-] No default credentials found")
        return False


async def run_poc():
    """Execute authentication tests"""
    bypass_result = await test_auth_bypass()
    creds_result = await test_default_credentials()
    
    return bypass_result or creds_result


if __name__ == "__main__":
    try:
        result = asyncio.run(run_poc())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\\n[!] Interrupted")
        sys.exit(130)
''',

    "rate_limit": '''#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║  POC: {name} - Rate Limiting Test
║  Target: {target}
║  Author: {author} <{email}>
║  Date: {date}
║  Description: {description}
║  
║  Tests rate limiting implementation on sensitive endpoints
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import asyncio
import time
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent.parent))

from app.lib.recon import GAZERecon, ReconResponse


# ══════════════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════════════

CONFIG = {{
    "target": "{target}",
    "endpoint": "{endpoint}",
    "method": "{method}",
    
    # Rate limit testing
    "requests_per_test": 100,
    "concurrency": 50,
    "expected_limit": 10,  # Expected requests per minute
    
    "test_payload": {{}},  # Payload for POST requests
    "headers": {{}},
}}


# ══════════════════════════════════════════════════════════════════════════════
# Rate Limit Test
# ══════════════════════════════════════════════════════════════════════════════

async def test_rate_limit():
    """Test if rate limiting is properly implemented"""
    print(f"[*] Testing rate limiting on {{CONFIG['endpoint']}}")
    print(f"[*] Sending {{CONFIG['requests_per_test']}} requests...")
    
    results = {{
        "success": 0,
        "rate_limited": 0,
        "errors": 0,
    }}
    
    async with GAZERecon(
        headers=CONFIG["headers"],
        verbose=False,
        delay=0,  # No delay - testing limits
    ) as recon:
        
        url = f"https://{{CONFIG['target']}}{{CONFIG['endpoint']}}"
        
        start_time = time.time()
        
        async def make_request():
            if CONFIG["method"] == "POST":
                response = await recon.post(url, CONFIG["test_payload"])
            else:
                response = await recon.get(url)
            
            if response.status == 429:
                results["rate_limited"] += 1
            elif response.is_success:
                results["success"] += 1
            else:
                results["errors"] += 1
            
            return response
        
        tasks = [make_request() for _ in range(CONFIG["requests_per_test"])]
        await asyncio.gather(*tasks)
        
        elapsed = time.time() - start_time
        
        print(f"\\n[*] Results:")
        print(f"    Successful: {{results['success']}}")
        print(f"    Rate Limited (429): {{results['rate_limited']}}")
        print(f"    Errors: {{results['errors']}}")
        print(f"    Duration: {{elapsed:.2f}}s")
        print(f"    Rate: {{CONFIG['requests_per_test'] / elapsed:.1f}} req/s")
        
        if results["rate_limited"] == 0:
            print("\\n[!] NO RATE LIMITING DETECTED!")
            print("[!] Endpoint may be vulnerable to abuse")
            return True
        else:
            limit_ratio = results["rate_limited"] / CONFIG["requests_per_test"]
            print(f"\\n[+] Rate limiting active ({{limit_ratio:.1%}} blocked)")
            return False


async def run_poc():
    """Execute rate limit tests"""
    return await test_rate_limit()


if __name__ == "__main__":
    try:
        result = asyncio.run(run_poc())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\\n[!] Interrupted")
        sys.exit(130)
''',

    "injection": '''#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║  POC: {name} - Injection Testing
║  Target: {target}
║  Author: {author} <{email}>
║  Date: {date}
║  Description: {description}
║  
║  Tests for SQL injection, NoSQL injection, and command injection
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import asyncio
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent.parent))

from app.lib.recon import GAZERecon, ReconResponse


# ══════════════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════════════

CONFIG = {{
    "target": "{target}",
    "endpoint": "{endpoint}",
    "method": "{method}",
    "param_field": "id",  # Field to inject
    
    "headers": {{}},
}}

# Injection payloads (sanitized for detection, not exploitation)
SQL_PAYLOADS = [
    "' OR '1'='1",
    "1' AND '1'='1",
    "1 OR 1=1",
    "'; DROP TABLE users--",
    "1' UNION SELECT NULL--",
]

NOSQL_PAYLOADS = [
    '{{"$gt": ""}}',
    '{{"$ne": null}}',
    '{{"$regex": ".*"}}',
]

ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "ORA-",
    "PostgreSQL",
    "sqlite3",
    "mongodb",
    "pymongo",
    "stack trace",
    "exception",
]


# ══════════════════════════════════════════════════════════════════════════════
# Validators
# ══════════════════════════════════════════════════════════════════════════════

def injection_validator(response: ReconResponse) -> bool:
    """Detect potential injection vulnerabilities"""
    body_lower = response.body.lower()
    
    # Check for error signatures
    for sig in ERROR_SIGNATURES:
        if sig in body_lower:
            return True
    
    # Check for unusual response times (blind injection)
    if response.response_time_ms > 5000:
        return True
    
    return False


# ══════════════════════════════════════════════════════════════════════════════
# Tests
# ══════════════════════════════════════════════════════════════════════════════

async def test_sql_injection():
    """Test for SQL injection"""
    print("[*] Testing SQL injection payloads...")
    
    async with GAZERecon(headers=CONFIG["headers"], verbose=True) as recon:
        url = f"https://{{CONFIG['target']}}{{CONFIG['endpoint']}}"
        
        hits = await recon.fuzz(
            url=url,
            payloads=SQL_PAYLOADS,
            method=CONFIG["method"],
            payload_field=CONFIG["param_field"],
            validators=[injection_validator],
        )
        
        if hits:
            print(f"[!] POTENTIAL SQL INJECTION - {{len(hits)}} indicators")
            return True
        
        print("[-] No SQL injection indicators found")
        return False


async def run_poc():
    """Execute injection tests"""
    sql_result = await test_sql_injection()
    return sql_result


if __name__ == "__main__":
    try:
        result = asyncio.run(run_poc())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\\n[!] Interrupted")
        sys.exit(130)
''',
}


# ══════════════════════════════════════════════════════════════════════════════
# POC Scaffold Class
# ══════════════════════════════════════════════════════════════════════════════

class POCScaffold:
    """POC scaffold generator"""
    
    def __init__(self, output_dir: str = "./pocs"):
        self.output_dir = Path(output_dir)
    
    def generate(
        self,
        name: str,
        template: str = "default",
        author: str = "Security Team",
        email: str = "security@hubtel.com",
        target: str = "api.hubtel.com",
        endpoint: str = "/api/v1/endpoint/{n}",
        method: str = "GET",
        description: str = "Security validation POC",
    ) -> Path:
        """
        Generate a new POC script.
        
        Args:
            name: POC name (will be used as filename)
            template: Template to use (default, idor, auth, rate_limit, injection)
            author: Author name
            email: Author email
            target: Target domain
            endpoint: API endpoint
            method: HTTP method
            description: POC description
        
        Returns:
            Path to generated file
        """
        if template not in TEMPLATES:
            raise ValueError(f"Unknown template: {template}. Available: {list(TEMPLATES.keys())}")
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate content
        content = TEMPLATES[template].format(
            name=name,
            author=author,
            email=email,
            target=target,
            endpoint=endpoint,
            method=method,
            description=description,
            date=datetime.now().strftime("%Y-%m-%d"),
        )
        
        # Write file
        filename = f"poc_{name.lower().replace(' ', '_')}.py"
        filepath = self.output_dir / filename
        filepath.write_text(content)
        
        print(f"{Colors.GREEN}[+]{Colors.RESET} Created: {filepath}")
        return filepath
    
    def interactive(self) -> Path:
        """Interactive POC generation"""
        print(BANNER)
        
        print(f"{Colors.CYAN}POC Configuration{Colors.RESET}")
        print("-" * 40)
        
        name = input(f"POC Name: ").strip() or "unnamed_poc"
        author = input(f"Author [{os.getenv('USER', 'Security Team')}]: ").strip() or os.getenv('USER', 'Security Team')
        email = input(f"Email [security@hubtel.com]: ").strip() or "security@hubtel.com"
        target = input(f"Target [api.hubtel.com]: ").strip() or "api.hubtel.com"
        endpoint = input(f"Endpoint [/api/v1/endpoint/{{n}}]: ").strip() or "/api/v1/endpoint/{n}"
        method = input(f"Method [GET]: ").strip().upper() or "GET"
        
        print(f"\nAvailable templates: {', '.join(TEMPLATES.keys())}")
        template = input(f"Template [default]: ").strip() or "default"
        
        description = input(f"Description: ").strip() or "Security validation POC"
        
        return self.generate(
            name=name,
            template=template,
            author=author,
            email=email,
            target=target,
            endpoint=endpoint,
            method=method,
            description=description,
        )
    
    @staticmethod
    def list_templates() -> None:
        """Print available templates"""
        print(f"\n{Colors.CYAN}Available Templates:{Colors.RESET}")
        print("-" * 40)
        templates_info = {
            "default": "Standard enumeration POC",
            "idor": "IDOR/BOLA access control testing",
            "auth": "Authentication bypass testing",
            "rate_limit": "Rate limiting validation",
            "injection": "Injection vulnerability testing",
        }
        for name, desc in templates_info.items():
            print(f"  {Colors.GREEN}{name:12}{Colors.RESET} - {desc}")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="GAZE POC Scaffold Generator")
    subparsers = parser.add_subparsers(dest="command")
    
    # New POC command
    new_parser = subparsers.add_parser("new", help="Create new POC")
    new_parser.add_argument("name", nargs="?", help="POC name")
    new_parser.add_argument("-t", "--template", default="default", help="Template to use")
    new_parser.add_argument("--target", default="api.hubtel.com", help="Target domain")
    new_parser.add_argument("-e", "--endpoint", default="/api/v1/endpoint/{n}", help="API endpoint")
    new_parser.add_argument("-X", "--method", default="GET", help="HTTP method")
    new_parser.add_argument("-o", "--output", default="./pocs", help="Output directory")
    new_parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    
    # List templates command
    subparsers.add_parser("templates", help="List available templates")
    
    args = parser.parse_args()
    
    scaffold = POCScaffold(output_dir=args.output if hasattr(args, 'output') else "./pocs")
    
    if args.command == "new":
        if args.interactive or not args.name:
            scaffold.interactive()
        else:
            scaffold.generate(
                name=args.name,
                template=args.template,
                target=args.target,
                endpoint=args.endpoint,
                method=args.method,
            )
    elif args.command == "templates":
        scaffold.list_templates()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
