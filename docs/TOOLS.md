# GAZE Security Tools Library

## Overview

The GAZE Security Tools Library provides three integrated tools for security assessments:

| Tool | Purpose |
|------|---------|
| **GAZERecon** | Async HTTP reconnaissance and enumeration |
| **POCScaffold** | Security POC script generator |
| **SecurityReporter** | Professional report generation (Word/PDF) |

## Installation

The tools are included in the Security platform. For standalone use:

```bash
pip install aiohttp structlog python-docx jinja2 weasyprint
```

---

## 1. GAZERecon

Async HTTP reconnaissance toolkit for API enumeration, IDOR testing, and vulnerability validation.

### Features

- 🚀 Async HTTP requests with connection pooling
- 📊 Range and wordlist enumeration
- ✅ Custom response validators
- 🔒 Proxy support (HTTP/SOCKS)
- ⏱️ Rate limiting and delay controls
- 📁 Multiple output formats (JSON, CSV, TXT)
- 📈 Progress tracking with ETA

### Quick Start

```python
import asyncio
from app.lib import GAZERecon, Validators

async def main():
    async with GAZERecon(
        token="eyJhbGciOiJIUzI1NiIs...",
        verbose=True,
    ) as recon:
        # Single request
        response = await recon.get("https://api.hubtel.com/v1/users/1")
        print(f"Status: {response.status}")
        
        # Range enumeration
        hits = await recon.enumerate_range(
            url_template="https://api.hubtel.com/v1/users/{n}",
            start=1,
            end=1000,
            validators=[Validators.status_ok, Validators.has_json_data],
            concurrency=20,
        )
        
        print(f"Found {len(hits)} accessible users")

asyncio.run(main())
```

### Synchronous Wrapper

```python
from app.lib import run_recon, Validators

hits = run_recon(
    "https://api.hubtel.com/v1/users/{n}",
    start=1,
    end=1000,
    token="eyJ...",
    validators=[Validators.status_ok],
)
```

### Built-in Validators

| Validator | Description |
|-----------|-------------|
| `Validators.status_ok` | Match 2xx responses |
| `Validators.status_not_404` | Match anything except 404 |
| `Validators.status_not_401_403` | Match anything except auth errors |
| `Validators.has_json_data` | Match non-empty JSON responses |
| `Validators.body_not_empty` | Match responses with content |
| `Validators.contains_email` | Match responses with email addresses |
| `Validators.contains_phone` | Match responses with phone numbers |
| `Validators.contains_sensitive` | Match responses with sensitive data patterns |

### Custom Validators

```python
def custom_validator(response: ReconResponse) -> bool:
    """Check for specific data exposure"""
    if response.status == 200:
        data = response.json()
        if data and "balance" in data:
            return True
    return False

# Use in enumeration
hits = await recon.enumerate_range(
    url_template="https://api.hubtel.com/v1/accounts/{n}",
    start=1000,
    end=9999,
    validators=[custom_validator],
)
```

### Factory Validators

```python
# Match unique response bodies
seen = set()
unique_validator = Validators.unique_body(seen)

# Match responses larger than threshold
large_body = Validators.body_length_greater_than(1000)

# Match responses with specific JSON field
has_email = Validators.json_field_exists("user.email")
```

### Wordlist Enumeration

```python
wordlist = ["admin", "test", "dev", "staging", "api"]

hits = await recon.enumerate_wordlist(
    url_template="https://api.hubtel.com/{w}/health",
    wordlist=wordlist,
    validators=[Validators.status_ok],
)
```

### Fuzzing

```python
payloads = ["' OR '1'='1", "<script>alert(1)</script>", "{{7*7}}"]

hits = await recon.fuzz(
    url="https://api.hubtel.com/v1/search",
    payloads=payloads,
    method="POST",
    payload_field="query",
    validators=[Validators.contains_sensitive],
)
```

### Configuration Options

```python
recon = GAZERecon(
    token="Bearer token",           # Authorization header
    headers={"X-Custom": "value"},  # Custom headers
    proxy="http://127.0.0.1:8080",  # Proxy URL (Burp, etc.)
    timeout=30,                      # Request timeout
    verify_ssl=True,                 # SSL verification
    delay=0.1,                       # Delay between requests
    max_retries=3,                   # Retry attempts
    verbose=True,                    # Verbose logging
    quiet=False,                     # Suppress output
)
```

### Output Export

```python
from app.lib import OutputExporter

# Export to different formats
OutputExporter.to_json(hits, "findings.json")
OutputExporter.to_csv(hits, "findings.csv")
OutputExporter.to_txt(hits, "urls.txt")

# Or use built-in export
hits = await recon.enumerate_range(
    ...,
    output_file="results.json",
    output_format="json",  # json, csv, txt
)
```

### ReconResponse Object

```python
response = await recon.get(url)

# Properties
response.url            # Request URL
response.status         # HTTP status code
response.body           # Response body text
response.body_length    # Body length in bytes
response.body_hash      # MD5 hash (first 8 chars)
response.headers        # Response headers dict
response.response_time_ms  # Response time in ms
response.marker         # Enumeration value (e.g., "123")
response.is_success     # True if 2xx
response.is_client_error  # True if 4xx
response.is_server_error  # True if 5xx

# Methods
response.contains("secret")  # Check body contains text
response.json()              # Parse as JSON
response.to_dict()           # Convert to dict
```

---

## 2. POCScaffold

Generate boilerplate POC scripts for security testing.

### Quick Start

```python
from app.lib import POCScaffold

scaffold = POCScaffold(output_dir="./pocs")

# Generate with arguments
scaffold.generate(
    name="idor_customer_data",
    template="idor",
    author="Security Team",
    email="security@hubtel.com",
    target="api.hubtel.com",
    endpoint="/api/v1/customers/{n}",
    method="GET",
    description="Test IDOR on customer endpoint",
)
```

### Interactive Mode

```python
scaffold = POCScaffold()
scaffold.interactive()  # Prompts for all options
```

### Available Templates

| Template | Description |
|----------|-------------|
| `default` | Standard enumeration POC |
| `idor` | IDOR/BOLA access control testing |
| `auth` | Authentication bypass testing |
| `rate_limit` | Rate limiting validation |
| `injection` | SQL/NoSQL injection testing |

### Generated POC Structure

Each POC includes:

- Configuration section with target details
- Custom validator functions
- Integration with GAZERecon
- Proper error handling
- Exit codes for CI/CD integration

### CLI Usage

```bash
# Interactive
python -m app.lib.scaffold new

# With arguments
python -m app.lib.scaffold new my_poc --template idor --target api.hubtel.com

# List templates
python -m app.lib.scaffold templates
```

---

## 3. SecurityReporter

Generate professional security assessment reports.

### Quick Start

```python
from app.lib import SecurityReporter, AssessmentData, FindingData

# Create findings
findings = [
    FindingData(
        id="VULN-001",
        title="SQL Injection in Login Form",
        severity="critical",
        status="open",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-89",
        description="The login form is vulnerable to SQL injection...",
        impact="An attacker can bypass authentication...",
        steps_to_reproduce="1. Navigate to /login\n2. Enter payload...",
        poc_code="curl -X POST ... -d 'username=admin' OR '1'='1'--'",
        recommendation="Use parameterized queries or an ORM.",
    ),
    FindingData(
        id="VULN-002",
        title="Missing Rate Limiting on API",
        severity="medium",
        status="open",
        cvss_score=5.3,
        cwe_id="CWE-307",
        description="No rate limiting on authentication endpoint...",
        recommendation="Implement rate limiting (e.g., 10 req/min).",
    ),
]

# Create assessment
assessment = AssessmentData(
    id="ASM-2025-001",
    name="Q1 2025 Security Assessment",
    asset_name="Customer Portal",
    assessment_type="penetration_test",
    status="completed",
    start_date="2025-01-15",
    end_date="2025-01-20",
    executive_summary="This assessment identified critical vulnerabilities...",
    methodology="OWASP Testing Guide v4.2",
    findings=findings,
    assessor_name="John Doe",
    assessor_email="john.doe@hubtel.com",
)

# Generate reports
reporter = SecurityReporter()
reporter.generate_word(assessment, "report.docx")
reporter.generate_pdf(assessment, "report.pdf")
```

### From Database Model

```python
from app.lib import SecurityReporter
from app.models import Assessment

# Get assessment from database
assessment = Assessment.query.get(assessment_id)

# Convert to report format
assessment_data = SecurityReporter.from_db_assessment(assessment)

# Generate reports
reporter = SecurityReporter()
reporter.generate_word(assessment_data, "report.docx")
```

### Report Configuration

```python
from app.lib import SecurityReporter, ReportConfig

config = ReportConfig(
    company_name="GAZE Limited",
    company_logo="/path/to/logo.png",
    report_title="Security Assessment Report",
    classification="CONFIDENTIAL",
    include_executive_summary=True,
    include_methodology=True,
    include_technical_details=True,
    include_evidence=True,
    include_remediation=True,
)

reporter = SecurityReporter(config)
```

### Report Sections

Word and PDF reports include:

1. **Title Page** - Company branding, classification, dates
2. **Executive Summary** - High-level overview, findings count by severity
3. **Findings Summary** - Table of all findings
4. **Detailed Findings** - Full technical details per finding
5. **Methodology** - Testing approach (optional)
6. **Remediation Summary** - Prioritized fix recommendations

### Finding Severity Colors

| Severity | Color |
|----------|-------|
| Critical | 🔴 Red (#DC2626) |
| High | 🟠 Orange (#EA580C) |
| Medium | 🟡 Yellow (#CA8A04) |
| Low | 🟢 Green (#16A34A) |
| Informational | 🔵 Blue (#2563EB) |

---

## Integration Examples

### Complete Assessment Workflow

```python
import asyncio
from app.lib import (
    GAZERecon, Validators,
    POCScaffold,
    SecurityReporter, AssessmentData, FindingData,
)

async def run_assessment():
    # 1. Generate POC for testing
    scaffold = POCScaffold()
    poc_path = scaffold.generate(
        name="idor_test",
        template="idor",
        target="api.hubtel.com",
        endpoint="/api/v1/users/{n}",
    )
    print(f"POC generated: {poc_path}")
    
    # 2. Run reconnaissance
    findings = []
    
    async with GAZERecon(token="...", verbose=True) as recon:
        hits = await recon.enumerate_range(
            url_template="https://api.hubtel.com/v1/users/{n}",
            start=1,
            end=100,
            validators=[Validators.status_ok],
        )
        
        if hits:
            findings.append(FindingData(
                id="VULN-001",
                title="IDOR on User Endpoint",
                severity="high",
                status="open",
                cvss_score=7.5,
                cwe_id="CWE-639",
                description=f"Found {len(hits)} accessible user records",
                recommendation="Implement proper authorization checks",
            ))
    
    # 3. Generate report
    assessment = AssessmentData(
        id="ASM-001",
        name="API Security Assessment",
        asset_name="GAZE API",
        assessment_type="penetration_test",
        status="completed",
        findings=findings,
    )
    
    reporter = SecurityReporter()
    reporter.generate_word(assessment, "assessment_report.docx")
    reporter.generate_pdf(assessment, "assessment_report.pdf")
    
    print("Assessment complete!")

asyncio.run(run_assessment())
```

### Flask Route Integration

```python
from flask import Blueprint, send_file
from app.lib import SecurityReporter
from app.models import Assessment

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/assessments/<int:id>/report.docx')
def download_word_report(id):
    assessment = Assessment.query.get_or_404(id)
    assessment_data = SecurityReporter.from_db_assessment(assessment)
    
    reporter = SecurityReporter()
    
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as f:
        reporter.generate_word(assessment_data, f.name)
        return send_file(
            f.name,
            as_attachment=True,
            download_name=f"{assessment.name}_report.docx",
        )
```

---

## Security Considerations

### Rate Limiting

Always use appropriate delays when testing production systems:

```python
recon = GAZERecon(delay=0.5)  # 500ms between requests
```

### Proxy Usage

Route traffic through Burp Suite for inspection:

```python
recon = GAZERecon(
    proxy="http://127.0.0.1:8080",
    verify_ssl=False,  # Required for Burp's certificate
)
```

### Authorization

Always ensure you have proper authorization before testing:

```python
# Good: Testing your own systems
recon = GAZERecon(token=your_api_token)

# Never: Unauthorized testing
```

---

## API Reference

### GAZERecon

| Method | Description |
|--------|-------------|
| `get(url)` | HTTP GET request |
| `post(url, payload)` | HTTP POST request |
| `put(url, payload)` | HTTP PUT request |
| `delete(url)` | HTTP DELETE request |
| `enumerate_range(...)` | Enumerate numeric range |
| `enumerate_wordlist(...)` | Enumerate from wordlist |
| `fuzz(...)` | Fuzz parameter with payloads |
| `close()` | Close session |

### POCScaffold

| Method | Description |
|--------|-------------|
| `generate(...)` | Generate POC from template |
| `interactive()` | Interactive POC generation |
| `list_templates()` | Show available templates |

### SecurityReporter

| Method | Description |
|--------|-------------|
| `generate_word(assessment, path)` | Generate Word document |
| `generate_pdf(assessment, path)` | Generate PDF document |
| `generate_html(assessment)` | Generate HTML content |
| `from_db_assessment(model)` | Convert DB model to data class |

---

## Changelog

### v2.0.0
- Complete rewrite with async support
- Integration with Security platform
- New POC templates
- PDF generation support
- Improved validators

### v1.0.0
- Initial release
- Basic enumeration
- Word report generation
