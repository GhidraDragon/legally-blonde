import re
import time
import random
import json
import urllib.parse
import requests
import html
from bs4 import BeautifulSoup
from pathlib import Path
from patterns import VULN_PATTERNS, HEADER_PATTERNS, VULN_EXPLANATIONS

CUSTOM_HEADERS = {"User-Agent":"ImprovedSecurityScanner/1.0"}
MAX_BODY_SNIPPET_LEN = 5000
ENABLE_HEADER_SCANNING = True
ENABLE_FORM_PARSING = True

def label_entry(label, tactic, snippet, confidence=1.0):
    expl = VULN_EXPLANATIONS.get(label, "No explanation")
    return (label, tactic, snippet, expl, confidence)

def normalize_and_decode(text):
    if not text: return text
    return html.unescape(urllib.parse.unquote(text)).lower()

def multiple_decode_passes(text, passes=3):
    c = text
    for _ in range(passes):
        c = urllib.parse.unquote(c)
        c = html.unescape(c)
    return c.lower()

def scan_for_vuln_patterns(snippet):
    findings = []
    n = normalize_and_decode(snippet)
    m = multiple_decode_passes(snippet, 2)
    for label, pattern in VULN_PATTERNS.items():
        for match in pattern.finditer(n):
            s = match.group(0)
            if len(s) > 200: s = s[:200] + "..."
            findings.append(label_entry(label, "pattern-based detection", s))
        for match in pattern.finditer(m):
            s = match.group(0)
            if len(s) > 200: s = s[:200] + "..."
            findings.append(label_entry(label, "pattern-based detection", s))
    return list(set(findings))

def dom_based_xss_detection(ht):
    res = []
    try:
        soup = BeautifulSoup(ht,"lxml")
    except:
        return res
    for s in soup.find_all("script"):
        if s.string and re.search(r"(alert|document\.cookie|<script)", s.string, re.IGNORECASE):
            sn = s.string.strip()
            if len(sn) > 200: sn = sn[:200] + "..."
            res.append(label_entry("XSS","DOM-based detection", sn))
    for tag in soup.find_all():
        for attr in tag.attrs:
            if attr.lower().startswith("on"):
                a = f"{attr}={tag.attrs[attr]}"
                res.append(label_entry("XSS","DOM-based detection", a))
    return res

def scan_response_headers(headers):
    findings = []
    if not headers:
        return findings
    for h in HEADER_PATTERNS["Missing Security Headers"]:
        if h.lower() not in [k.lower() for k in headers.keys()]:
            findings.append(label_entry("Missing Security Headers","header-based detection", h))
    srv = headers.get("Server","")
    if HEADER_PATTERNS["Outdated or Insecure Server"].search(srv):
        findings.append(label_entry("Outdated or Insecure Server","header-based detection", srv))
    sc = headers.get("Set-Cookie","")
    if sc and ("secure" not in sc.lower() or "httponly" not in sc.lower()):
        findings.append(label_entry("Cookies lack 'Secure'/'HttpOnly'","header-based detection", sc))
    return findings

def parse_suspicious_forms(ht):
    res = []
    t = normalize_and_decode(ht)
    form_p = re.compile(r"<form\b.*?</form>", re.IGNORECASE|re.DOTALL)
    fs = form_p.findall(t)
    for f_ in fs:
        c = f_[:200] + "..." if len(f_) > 200 else f_
        mm = re.search(r"method\s*=\s*(['\"])(.*?)\1", f_, re.IGNORECASE|re.DOTALL)
        if mm and mm.group(2).lower() == "get":
            if re.search(r"type\s*=\s*(['\"])(password|hidden)\1", f_, re.IGNORECASE):
                res.append(label_entry("Form uses GET with password/hidden","form-based detection", c))
        if re.search(r"name\s*=\s*(['\"])(cmd|shell|token)\1", f_, re.IGNORECASE):
            res.append(label_entry("Suspicious form fields (cmd/shell/token)","form-based detection", c))
        if mm and mm.group(2).lower() == "post" and not re.search(r"name\s*=\s*(['\"])(csrf|csrf_token)\1", f_, re.IGNORECASE):
            res.append(label_entry("POST form without CSRF token","form-based detection", c))
    return res

def analyze_query_params(url):
    from urllib.parse import urlparse, parse_qs
    findings = []
    u = urlparse(url)
    qs = parse_qs(u.query)
    for p, vals in qs.items():
        dp = normalize_and_decode(p)
        if re.search(r"(cmd|exec|shell|script|token|redir|redirect)", dp, re.IGNORECASE):
            findings.append(label_entry("Suspicious param name:","query-param detection", p))
        for v in vals:
            dv = normalize_and_decode(v)
            if re.search(r"(<>|<script>|' or 1=1|../../|jsessionid=|%0a|%0d)", dv, re.IGNORECASE):
                findings.append(label_entry("Suspicious param value in","query-param detection", f"{p}={v}"))
    return findings

def fuzz_injection_tests(url):
    fs = []
    payloads = [
        "' OR '1'='1","<script>alert(1)</script>","; ls;","&& cat /etc/passwd",
        "<img src=x onerror=alert(2)>","'; DROP TABLE users; --","|| ping -c 4 127.0.0.1 ||"
    ]
    for p in payloads:
        time.sleep(random.uniform(1.2,2.5))
        try:
            tu = f"{url}?inj={urllib.parse.quote(p)}"
            r = requests.get(tu, timeout=3, headers=CUSTOM_HEADERS)
            fs.extend(scan_for_vuln_patterns(r.text))
        except:
            pass
    return fs

def repeated_disruption_test(url, attempts=3):
    findings = []
    for _ in range(attempts):
        time.sleep(random.uniform(1.0,2.0))
        try:
            r = requests.get(url, timeout=3, headers=CUSTOM_HEADERS)
            if r.status_code >= 500:
                findings.append(label_entry("Service Disruption","frequent-request detection", str(r.status_code)))
        except:
            findings.append(label_entry("Service Disruption","frequent-request detection","Exception"))
    return findings

def extract_js_functions(ht):
    fns = []
    sc = re.findall(r"<script[^>]*>(.*?)</script>", ht, re.IGNORECASE|re.DOTALL)
    for sb in sc:
        m = re.findall(r"(function\s+[a-zA-Z0-9_$]+\s*\([^)]*\)\s*\{.*?\})", sb, re.DOTALL)
        for mm in m:
            if len(mm) > 400: mm = mm[:400] + "..."
            fns.append(mm.strip())
    return fns

def scan_target(url):
    ds = analyze_query_params(url)
    ds.extend(fuzz_injection_tests(url))
    ds.extend(repeated_disruption_test(url))
    try:
        time.sleep(random.uniform(1.5,3.0))
        r = requests.get(url, timeout=5, headers=CUSTOM_HEADERS)
        b = r.text[:MAX_BODY_SNIPPET_LEN]
        ds.extend(scan_for_vuln_patterns(b))
        if ENABLE_HEADER_SCANNING:
            ds.extend(scan_response_headers(r.headers))
        if ENABLE_FORM_PARSING:
            ds.extend(parse_suspicious_forms(b))
        ds.extend(dom_based_xss_detection(b))
        return {
            "url": url,
            "status_code": r.status_code,
            "reason": r.reason,
            "server": r.headers.get("Server","Unknown"),
            "matched_details": ds,
            "extracted_js_functions": extract_js_functions(r.text),
            "body": r.text
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "matched_details": ds,
            "server": "Unknown",
            "extracted_js_functions": [],
            "body": ""
        }
