#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                              HUBTEL RECON                                      ║
║                    Async HTTP Reconnaissance Library                           ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Organization : GAZE Limited                                                 ║
║  Team         : Security Operations                                            ║
║  Purpose      : Automated HTTP enumeration and vulnerability validation        ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Features:
    - Async HTTP requests with connection pooling
    - Range and wordlist enumeration
    - Custom response validators
    - Proxy support (HTTP/SOCKS)
    - Rate limiting and delay controls
    - Multiple output formats (JSON, CSV, TXT)
    - Progress tracking with ETA
    - Automatic retry with backoff

Usage:
    # CLI Mode
    python recon.py https://api.hubtel.com/v1/users/{n} --range 1-1000
    
    # Library Mode
    from app.lib.recon import GAZERecon
    recon = GAZERecon(token="...", verbose=True)
    hits = await recon.enumerate_range(url, 1, 1000)
"""
import asyncio
import aiohttp
import json
import csv
import time
import re
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable, Any, List, Dict, Union
from datetime import datetime
from pathlib import Path
import structlog

logger = structlog.get_logger()


# ══════════════════════════════════════════════════════════════════════════════
# Colors for CLI output
# ══════════════════════════════════════════════════════════════════════════════

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# ══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ReconResponse:
    """Structured HTTP response with metadata"""
    url: str
    method: str
    status: int
    headers: Dict[str, str]
    body: str
    response_time_ms: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    marker: Optional[str] = None  # The enumeration value (e.g., "123" or "admin")
    body_hash: str = ""
    body_length: int = 0
    error: Optional[str] = None
    
    def __post_init__(self):
        self.body_length = len(self.body)
        self.body_hash = hashlib.md5(self.body.encode()).hexdigest()[:8]
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300
    
    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status < 500
    
    @property
    def is_server_error(self) -> bool:
        return self.status >= 500
    
    def contains(self, text: str, case_sensitive: bool = False) -> bool:
        """Check if body contains text"""
        if case_sensitive:
            return text in self.body
        return text.lower() in self.body.lower()
    
    def json(self) -> Optional[dict]:
        """Parse body as JSON"""
        try:
            return json.loads(self.body)
        except json.JSONDecodeError:
            return None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            'url': self.url,
            'method': self.method,
            'status': self.status,
            'marker': self.marker,
            'body_length': self.body_length,
            'body_hash': self.body_hash,
            'response_time_ms': self.response_time_ms,
            'timestamp': self.timestamp,
            'error': self.error,
        }


@dataclass
class EnumerationResult:
    """Results from an enumeration run"""
    target: str
    method: str
    total_requests: int
    successful_hits: int
    start_time: str
    end_time: str
    duration_seconds: float
    hits: List[ReconResponse] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'target': self.target,
            'method': self.method,
            'total_requests': self.total_requests,
            'successful_hits': self.successful_hits,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration_seconds': self.duration_seconds,
            'hits': [h.to_dict() for h in self.hits],
            'error_count': len(self.errors),
        }


# ══════════════════════════════════════════════════════════════════════════════
# Built-in Validators
# ══════════════════════════════════════════════════════════════════════════════

class Validators:
    """Pre-built response validators"""
    
    @staticmethod
    def status_ok(response: ReconResponse) -> bool:
        """Match 2xx responses"""
        return response.is_success
    
    @staticmethod
    def status_not_404(response: ReconResponse) -> bool:
        """Match anything except 404"""
        return response.status != 404
    
    @staticmethod
    def status_not_401_403(response: ReconResponse) -> bool:
        """Match anything except auth errors"""
        return response.status not in [401, 403]
    
    @staticmethod
    def has_json_data(response: ReconResponse) -> bool:
        """Match responses with non-empty JSON data"""
        data = response.json()
        return data is not None and len(data) > 0
    
    @staticmethod
    def body_not_empty(response: ReconResponse) -> bool:
        """Match responses with content"""
        return response.body_length > 0
    
    @staticmethod
    def contains_email(response: ReconResponse) -> bool:
        """Match responses containing email addresses"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return bool(re.search(email_pattern, response.body))
    
    @staticmethod
    def contains_phone(response: ReconResponse) -> bool:
        """Match responses containing phone numbers"""
        phone_pattern = r'(?:\+233|0)[2-5]\d{8}'
        return bool(re.search(phone_pattern, response.body))
    
    @staticmethod
    def contains_sensitive(response: ReconResponse) -> bool:
        """Match responses with potentially sensitive data"""
        sensitive_patterns = [
            r'"password":', r'"token":', r'"secret":', r'"api_key":',
            r'"ssn":', r'"credit_card":', r'"cvv":',
            r'"private_key":', r'"access_token":'
        ]
        for pattern in sensitive_patterns:
            if re.search(pattern, response.body, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def unique_body(seen_hashes: set) -> Callable[[ReconResponse], bool]:
        """Factory: Match responses with unique body content"""
        def validator(response: ReconResponse) -> bool:
            if response.body_hash in seen_hashes:
                return False
            seen_hashes.add(response.body_hash)
            return True
        return validator
    
    @staticmethod
    def body_length_greater_than(min_length: int) -> Callable[[ReconResponse], bool]:
        """Factory: Match responses above certain length"""
        def validator(response: ReconResponse) -> bool:
            return response.body_length > min_length
        return validator
    
    @staticmethod
    def json_field_exists(field: str) -> Callable[[ReconResponse], bool]:
        """Factory: Match responses where JSON contains specific field"""
        def validator(response: ReconResponse) -> bool:
            data = response.json()
            if not data:
                return False
            # Support nested fields like "user.email"
            keys = field.split('.')
            current = data
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return False
            return True
        return validator


# ══════════════════════════════════════════════════════════════════════════════
# Output Exporters
# ══════════════════════════════════════════════════════════════════════════════

class OutputExporter:
    """Export results to various formats"""
    
    @staticmethod
    def to_json(responses: List[ReconResponse], filepath: str) -> None:
        """Export to JSON"""
        data = [r.to_dict() for r in responses]
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    @staticmethod
    def to_csv(responses: List[ReconResponse], filepath: str) -> None:
        """Export to CSV"""
        if not responses:
            return
        fieldnames = ['url', 'method', 'status', 'marker', 'body_length', 
                      'body_hash', 'response_time_ms', 'timestamp']
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in responses:
                writer.writerow({k: v for k, v in r.to_dict().items() if k in fieldnames})
    
    @staticmethod
    def to_txt(responses: List[ReconResponse], filepath: str) -> None:
        """Export URLs only"""
        with open(filepath, 'w') as f:
            for r in responses:
                f.write(f"{r.url}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Console Logger
# ══════════════════════════════════════════════════════════════════════════════

class ConsoleLogger:
    """Formatted console output"""
    
    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
    
    def info(self, msg: str) -> None:
        if not self.quiet:
            print(f"{Colors.CYAN}[*]{Colors.RESET} {msg}")
    
    def success(self, msg: str) -> None:
        if not self.quiet:
            print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")
    
    def warning(self, msg: str) -> None:
        if not self.quiet:
            print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")
    
    def error(self, msg: str) -> None:
        print(f"{Colors.RED}[-]{Colors.RESET} {msg}")
    
    def debug(self, msg: str) -> None:
        if self.verbose:
            print(f"{Colors.DIM}[D]{Colors.RESET} {msg}")
    
    def hit(self, response: ReconResponse) -> None:
        if not self.quiet:
            status_color = Colors.GREEN if response.is_success else Colors.YELLOW
            print(f"{Colors.GREEN}[HIT]{Colors.RESET} "
                  f"{status_color}{response.status}{Colors.RESET} | "
                  f"{response.body_length:>6} bytes | "
                  f"{response.response_time_ms:>6.0f}ms | "
                  f"{Colors.CYAN}{response.url}{Colors.RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# Main Recon Class
# ══════════════════════════════════════════════════════════════════════════════

class GAZERecon:
    """
    Async HTTP reconnaissance toolkit for GAZE security assessments.
    
    Example:
        async with GAZERecon(token="...") as recon:
            hits = await recon.enumerate_range(
                url_template="https://api.hubtel.com/v1/users/{n}",
                start=1,
                end=1000,
                validators=[Validators.status_ok, Validators.has_json_data]
            )
    """
    
    def __init__(
        self,
        token: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        verify_ssl: bool = True,
        delay: float = 0.0,
        max_retries: int = 3,
        verbose: bool = False,
        quiet: bool = False,
    ):
        self.token = token
        self.custom_headers = headers or {}
        self.proxy = proxy
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.verify_ssl = verify_ssl
        self.delay = delay
        self.max_retries = max_retries
        self.logger = ConsoleLogger(verbose=verbose, quiet=quiet)
        self._session: Optional[aiohttp.ClientSession] = None
        self._rate_limit_detected = False
    
    async def __aenter__(self):
        await self._create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def _create_session(self) -> None:
        """Create aiohttp session with connection pooling"""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30,
            ssl=self.verify_ssl
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout
        )
    
    async def close(self) -> None:
        """Close the session"""
        if self._session:
            await self._session.close()
            self._session = None
    
    def _build_headers(self) -> Dict[str, str]:
        """Build request headers"""
        headers = {
            'User-Agent': 'GAZERecon/2.0',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        headers.update(self.custom_headers)
        return headers
    
    async def _request(
        self,
        method: str,
        url: str,
        payload: Optional[dict] = None,
        marker: Optional[str] = None,
    ) -> ReconResponse:
        """Execute single HTTP request with retry logic"""
        if not self._session:
            await self._create_session()
        
        headers = self._build_headers()
        start_time = time.time()
        
        for attempt in range(self.max_retries):
            try:
                kwargs = {
                    'headers': headers,
                    'proxy': self.proxy,
                    'ssl': self.verify_ssl,
                }
                if payload:
                    kwargs['json'] = payload
                
                async with self._session.request(method, url, **kwargs) as resp:
                    body = await resp.text()
                    response_time = (time.time() - start_time) * 1000
                    
                    # Detect rate limiting
                    if resp.status == 429:
                        self._rate_limit_detected = True
                        retry_after = int(resp.headers.get('Retry-After', 5))
                        self.logger.warning(f"Rate limited. Waiting {retry_after}s...")
                        await asyncio.sleep(retry_after)
                        continue
                    
                    return ReconResponse(
                        url=url,
                        method=method,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        response_time_ms=response_time,
                        marker=marker,
                    )
                    
            except asyncio.TimeoutError:
                self.logger.debug(f"Timeout on attempt {attempt + 1}: {url}")
            except aiohttp.ClientError as e:
                self.logger.debug(f"Request error: {e}")
            
            if attempt < self.max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        # Return error response after all retries
        return ReconResponse(
            url=url,
            method=method,
            status=0,
            headers={},
            body="",
            response_time_ms=(time.time() - start_time) * 1000,
            marker=marker,
            error="Max retries exceeded"
        )
    
    async def get(self, url: str) -> ReconResponse:
        """GET request"""
        return await self._request("GET", url)
    
    async def post(self, url: str, payload: dict) -> ReconResponse:
        """POST request"""
        return await self._request("POST", url, payload)
    
    async def put(self, url: str, payload: dict) -> ReconResponse:
        """PUT request"""
        return await self._request("PUT", url, payload)
    
    async def delete(self, url: str) -> ReconResponse:
        """DELETE request"""
        return await self._request("DELETE", url)
    
    async def enumerate_range(
        self,
        url_template: str,
        start: int,
        end: int,
        method: str = "GET",
        payload_template: Optional[dict] = None,
        concurrency: int = 10,
        validators: Optional[List[Callable[[ReconResponse], bool]]] = None,
        zero_pad: int = 0,
        output_file: Optional[str] = None,
        output_format: str = "json",
        show_progress: bool = True,
    ) -> List[ReconResponse]:
        """
        Enumerate a numeric range.
        
        Args:
            url_template: URL with {n} placeholder
            start: Starting number
            end: Ending number
            method: HTTP method
            payload_template: JSON payload with {n} placeholder
            concurrency: Max concurrent requests
            validators: List of validator functions
            zero_pad: Zero-pad numbers (e.g., 4 -> 0001)
            output_file: Save hits to file
            output_format: json, csv, or txt
            show_progress: Show progress bar
        
        Returns:
            List of matching responses
        """
        validators = validators or [Validators.status_ok]
        hits: List[ReconResponse] = []
        total = end - start + 1
        completed = 0
        start_ts = datetime.utcnow()
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def process_item(n: int) -> Optional[ReconResponse]:
            nonlocal completed
            async with semaphore:
                marker = str(n).zfill(zero_pad) if zero_pad else str(n)
                url = url_template.replace("{n}", marker)
                
                payload = None
                if payload_template:
                    payload = json.loads(
                        json.dumps(payload_template).replace("{n}", marker)
                    )
                
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                
                response = await self._request(method, url, payload, marker)
                completed += 1
                
                if show_progress and completed % 100 == 0:
                    elapsed = (datetime.utcnow() - start_ts).total_seconds()
                    rate = completed / elapsed if elapsed > 0 else 0
                    eta = (total - completed) / rate if rate > 0 else 0
                    self.logger.info(f"Progress: {completed}/{total} ({rate:.1f}/s, ETA: {eta:.0f}s)")
                
                # Check validators
                if all(v(response) for v in validators):
                    self.logger.hit(response)
                    return response
                
                return None
        
        self.logger.info(f"Starting enumeration: {start}-{end} ({total} items)")
        self.logger.info(f"Concurrency: {concurrency}, Delay: {self.delay}s")
        
        tasks = [process_item(n) for n in range(start, end + 1)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ReconResponse):
                hits.append(result)
        
        end_ts = datetime.utcnow()
        duration = (end_ts - start_ts).total_seconds()
        
        self.logger.success(f"Completed: {total} requests in {duration:.1f}s")
        self.logger.success(f"Hits: {len(hits)}/{total}")
        
        if output_file and hits:
            if output_format == "json":
                OutputExporter.to_json(hits, output_file)
            elif output_format == "csv":
                OutputExporter.to_csv(hits, output_file)
            else:
                OutputExporter.to_txt(hits, output_file)
            self.logger.success(f"Saved to {output_file}")
        
        return hits
    
    async def enumerate_wordlist(
        self,
        url_template: str,
        wordlist: List[str],
        method: str = "GET",
        payload_template: Optional[dict] = None,
        concurrency: int = 10,
        validators: Optional[List[Callable[[ReconResponse], bool]]] = None,
        output_file: Optional[str] = None,
        output_format: str = "json",
        show_progress: bool = True,
    ) -> List[ReconResponse]:
        """
        Enumerate using a wordlist.
        
        Args:
            url_template: URL with {w} placeholder
            wordlist: List of words to enumerate
            method: HTTP method
            payload_template: JSON payload with {w} placeholder
            concurrency: Max concurrent requests
            validators: List of validator functions
            output_file: Save hits to file
            output_format: json, csv, or txt
            show_progress: Show progress bar
        
        Returns:
            List of matching responses
        """
        validators = validators or [Validators.status_not_404]
        hits: List[ReconResponse] = []
        total = len(wordlist)
        completed = 0
        start_ts = datetime.utcnow()
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def process_word(word: str) -> Optional[ReconResponse]:
            nonlocal completed
            async with semaphore:
                url = url_template.replace("{w}", word)
                
                payload = None
                if payload_template:
                    payload = json.loads(
                        json.dumps(payload_template).replace("{w}", word)
                    )
                
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                
                response = await self._request(method, url, payload, word)
                completed += 1
                
                if show_progress and completed % 50 == 0:
                    self.logger.info(f"Progress: {completed}/{total}")
                
                if all(v(response) for v in validators):
                    self.logger.hit(response)
                    return response
                
                return None
        
        self.logger.info(f"Starting wordlist enumeration: {total} items")
        
        tasks = [process_word(w) for w in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ReconResponse):
                hits.append(result)
        
        end_ts = datetime.utcnow()
        duration = (end_ts - start_ts).total_seconds()
        
        self.logger.success(f"Completed: {total} requests in {duration:.1f}s")
        self.logger.success(f"Hits: {len(hits)}/{total}")
        
        if output_file and hits:
            if output_format == "json":
                OutputExporter.to_json(hits, output_file)
            elif output_format == "csv":
                OutputExporter.to_csv(hits, output_file)
            else:
                OutputExporter.to_txt(hits, output_file)
            self.logger.success(f"Saved to {output_file}")
        
        return hits
    
    async def fuzz(
        self,
        url: str,
        payloads: List[str],
        method: str = "POST",
        payload_field: str = "input",
        validators: Optional[List[Callable[[ReconResponse], bool]]] = None,
        concurrency: int = 5,
    ) -> List[ReconResponse]:
        """
        Fuzz a parameter with multiple payloads.
        
        Args:
            url: Target URL
            payloads: List of payloads to test
            method: HTTP method
            payload_field: JSON field to inject into
            validators: Validator functions
            concurrency: Max concurrent requests
        
        Returns:
            List of interesting responses
        """
        validators = validators or [Validators.status_ok]
        hits: List[ReconResponse] = []
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def test_payload(payload: str) -> Optional[ReconResponse]:
            async with semaphore:
                data = {payload_field: payload}
                response = await self._request(method, url, data, payload)
                
                if all(v(response) for v in validators):
                    self.logger.hit(response)
                    return response
                return None
        
        tasks = [test_payload(p) for p in payloads]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ReconResponse):
                hits.append(result)
        
        return hits


# ══════════════════════════════════════════════════════════════════════════════
# Convenience function for sync code
# ══════════════════════════════════════════════════════════════════════════════

def run_recon(
    url_template: str,
    start: int,
    end: int,
    token: Optional[str] = None,
    validators: Optional[List[Callable]] = None,
    concurrency: int = 10,
) -> List[ReconResponse]:
    """
    Synchronous wrapper for quick enumeration.
    
    Example:
        from app.lib.recon import run_recon, Validators
        
        hits = run_recon(
            "https://api.hubtel.com/v1/users/{n}",
            start=1,
            end=1000,
            token="eyJ...",
            validators=[Validators.status_ok]
        )
    """
    async def _run():
        async with GAZERecon(token=token) as recon:
            return await recon.enumerate_range(
                url_template=url_template,
                start=start,
                end=end,
                validators=validators,
                concurrency=concurrency,
            )
    
    return asyncio.run(_run())
