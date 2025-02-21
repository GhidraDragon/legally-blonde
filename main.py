import os
import re
import html
import time
import json
import random
import heapq
import sqlite3
import urllib.parse
import requests
import concurrent.futures
import sys
from pathlib import Path
from bs4 import BeautifulSoup
from test_sites import test_sites
from driver_screenshot import scan_with_chromedriver

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    import joblib
    ML_CLASSIFIER_AVAILABLE = True
except ImportError:
    ML_CLASSIFIER_AVAILABLE = False

XSS_MODEL_PATH = "xss_js_model.joblib"
SQLI_MODEL_PATH = "sql_injection_model.joblib"
MULTI_MODELS_DIR = "ml_models"
MAX_BODY_SNIPPET_LEN = 5000
ENABLE_HEADER_SCANNING = True
ENABLE_FORM_PARSING = True
CUSTOM_HEADERS = {"User-Agent":"ImprovedSecurityScanner/1.0"}

VULN_PATTERNS = {
    "SQL Error": re.compile(r"(sql\s*exception|sql\s*syntax|warning.*mysql.*|unclosed\s*quotation\s*mark|microsoft\s*ole\s*db\s*provider|odbc\s*sql\s*server\s*driver|pg_query\()", re.IGNORECASE|re.DOTALL),
    "SQL Injection": re.compile(r"(\bunion\s+select\s|\bselect\s+\*\s+from\s|\bsleep\(|\b'or\s+1=1\b|\b'or\s+'a'='a\b|--|#|xp_cmdshell|information_schema)", re.IGNORECASE|re.DOTALL),
    "XSS": re.compile("|".join([
        r"<\s*script[^>]*?>.*?<\s*/\s*script\s*>",
        r"<\s*img[^>]+onerror\s*=.*?>",
        r"<\s*svg[^>]*on(load|error)\s*=",
        r"<\s*iframe\b.*?>",
        r"<\s*body\b[^>]*onload\s*=",
        r"javascript\s*:",
        r"<\s*\w+\s+on\w+\s*=",
        r"<\s*s\s*c\s*r\s*i\s*p\s*t[^>]*>",
        r"&#x3c;\s*script\s*&#x3e;",
        r"<scr(?:.*?)ipt>",
        r"</scr(?:.*?)ipt>",
        r"<\s*script[^>]*src\s*=.*?>",
        r"expression\s*\(",
        r"vbscript\s*:",
        r"mozbinding\s*:",
        r"javascript:alert\(document.domain\)",
        r"<script src=['\"]http://[^>]*?>"
    ]), re.IGNORECASE|re.DOTALL),
    "Directory Listing": re.compile(r"(<title>\s*index of\s*/\s*</title>|directory\s+listing\s+for)", re.IGNORECASE|re.DOTALL),
    "File Inclusion": re.compile(r"(include|require)(_once)?\s*\(.*?http://", re.IGNORECASE|re.DOTALL),
    "Server Error": re.compile(r"(internal\s+server\s+error|500\s+internal|traceback\s*\(most\s+recent\s+call\s+last\))", re.IGNORECASE|re.DOTALL),
    "Shellshock": re.compile(r"\(\)\s*\{:\;};", re.IGNORECASE|re.DOTALL),
    "Remote Code Execution": re.compile(r"(exec\(|system\(|shell_exec\(|/bin/sh|eval\(|\bpython\s+-c\s)", re.IGNORECASE|re.DOTALL),
    "LFI/RFI": re.compile(r"(etc/passwd|boot.ini|\\\\\\\\\.\\\\pipe\\\\|\\\.\\pipe\\)", re.IGNORECASE|re.DOTALL),
    "SSRF": re.compile(r"(127\.0\.0\.1|localhost|metadata\.google\.internal)", re.IGNORECASE|re.DOTALL),
    "Path Traversal": re.compile(r"(\.\./\.\./|\.\./|\.\.\\)", re.IGNORECASE|re.DOTALL),
    "Command Injection": re.compile(r"(\|\||&&|;|/bin/bash|/bin/zsh)", re.IGNORECASE|re.DOTALL),
    "WordPress Leak": re.compile(r"(wp-content|wp-includes|wp-admin)", re.IGNORECASE|re.DOTALL),
    "Java Error": re.compile(r"(java\.lang\.|exception\s+in\s+thread\s+\"main\")", re.IGNORECASE|re.DOTALL),
    "Open Redirect": re.compile(r"(=\s*https?:\/\/)", re.IGNORECASE|re.DOTALL),
    "Deserialization": re.compile(r"(java\.io\.objectinputstream|ysoserial|__proto__|constructor\.prototype)", re.IGNORECASE|re.DOTALL),
    "XXE": re.compile(r"(<!doctype\s+[^>]*\[.*<!entity\s+[^>]*system)", re.IGNORECASE|re.DOTALL),
    "File Upload": re.compile(r"(multipart/form-data.*filename=)", re.IGNORECASE|re.DOTALL),
    "Prototype Pollution": re.compile(r"(\.__proto__|object\.prototype|object\.setprototypeof)", re.IGNORECASE|re.DOTALL),
    "NoSQL Injection": re.compile(r"(db\.\w+\.find\(|\$\w+\{|{\s*\$where\s*:)", re.IGNORECASE|re.DOTALL),
    "Exposed Git Directory": re.compile(r"(\.git/HEAD|\.gitignore|\.git/config)", re.IGNORECASE|re.DOTALL),
    "Potential Secrets": re.compile(r"(aws_access_key_id|aws_secret_access_key|api_key|private_key|authorization:\s*bearer\s+[0-9a-z\-_\.]+)", re.IGNORECASE|re.DOTALL),
    "JWT Token Leak": re.compile(r"(eyjh[a-z0-9_-]*\.[a-z0-9_-]+\.[a-z0-9_-]+)", re.IGNORECASE|re.DOTALL),
    "ETC Shadow Leak": re.compile(r"/etc/shadow", re.IGNORECASE|re.DOTALL),
    "Possible Password Leak": re.compile(r"(password\s*=\s*\w+)", re.IGNORECASE|re.DOTALL),
    "CC Leak": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "CRLF Injection": re.compile(r"(\r\n|%0d%0a|%0A%0D)", re.IGNORECASE|re.DOTALL),
    "HTTP Request Smuggling": re.compile(r"(content-length:\s*\d+.*\r?\n\s*transfer-encoding:\s*chunked|transfer-encoding:\s*chunked.*\r?\n\s*content-length:\s*\d+)", re.IGNORECASE|re.DOTALL),
    "LDAP Injection": re.compile(r"(\(\w+=\*\)|\|\(\w+=\*\)|\(\w+~=\*)", re.IGNORECASE|re.DOTALL),
    "XPath Injection": re.compile(r"(/[^/]+/|\[[^\]]+\]|text\(\)=)", re.IGNORECASE|re.DOTALL),
    "Exposed S3 Bucket": re.compile(r"s3\.amazonaws\.com", re.IGNORECASE),
    "Exposed Azure Blob": re.compile(r"blob\.core\.windows\.net", re.IGNORECASE),
    "Exposed K8s Secrets": re.compile(r"kube[\s_-]*config|k8s[\s_-]*secret|kubeadm[\s_-]*token", re.IGNORECASE|re.DOTALL),
    "npm Token": re.compile(r"npm[_-]token_[a-z0-9]{36}", re.IGNORECASE|re.DOTALL)
}

HEADER_PATTERNS = {
    "Missing Security Headers": ["Content-Security-Policy","X-Content-Type-Options","X-Frame-Options","X-XSS-Protection","Strict-Transport-Security"],
    "Outdated or Insecure Server": re.compile(r"(apache/2\.2\.\d|nginx/1\.10\.\d|iis/6\.0|php/5\.2)", re.IGNORECASE),
}

VULN_EXPLANATIONS = {
    "SQL Error":"Server returned DB error messages.","SQL Injection":"Likely injection in SQL queries.","XSS":"Injected scripts.",
    "Directory Listing":"Exposed directory contents.","File Inclusion":"Local/remote file inclusion.",
    "Server Error":"HTTP 500 or similar.","Shellshock":"Bash vulnerability.","Remote Code Execution":"User input runs code.",
    "LFI/RFI":"File references for inclusion.","SSRF":"Server-Side Request Forgery.","Path Traversal":"Directory traversal.",
    "Command Injection":"Shell commands injected.","WordPress Leak":"WordPress paths/files.","Java Error":"Java exceptions or traces.",
    "Open Redirect":"Redirect to external URL.","Deserialization":"Unsafe object deserialization.","XXE":"XML External Entity usage.",
    "File Upload":"Multipart form can upload.","Prototype Pollution":"JS prototype manipulation.","NoSQL Injection":"NoSQL references.",
    "Exposed Git Directory":"Git config or HEAD visible.","Potential Secrets":"API keys or tokens leaked.","JWT Token Leak":"JWT tokens exposed.",
    "ETC Shadow Leak":"/etc/shadow reference.","Missing Security Headers":"Key headers absent.","Outdated or Insecure Server":"Old server.",
    "Cookies lack 'Secure'/'HttpOnly'":"Cookie flags missing.","Suspicious param name:":"Param name looks malicious.",
    "Suspicious param value in":"Param value looks malicious.","Form uses GET with password/hidden":"Sensitive data in GET.",
    "Suspicious form fields (cmd/shell/token)":"Malicious field names.","POST form without CSRF token":"Form missing CSRF token.",
    "Service Disruption":"5xx errors or repeated failures.","Possible Password Leak":"Possible credential leakage.",
    "CC Leak":"Credit card pattern found.","CRLF Injection":"CRLF discovered.","HTTP Request Smuggling":"Conflicting request headers.",
    "LDAP Injection":"Directory service injection.","XPath Injection":"XPath queries injected.",
    "Exposed S3 Bucket":"Possible public S3.","Exposed Azure Blob":"Unsecured Azure blob.","Exposed K8s Secrets":"Possible K8s secrets.",
    "npm Token":"npm token possibly leaked.","ChromeDriver Error":"Selenium error.","No explanation":"No explanation"
}

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

def extract_links_from_html(url, html_text):
    links = set()
    try:
        soup = BeautifulSoup(html_text, "lxml")
        for a in soup.find_all("a", href=True):
            u = urllib.parse.urljoin(url, a["href"])
            if u.startswith("http"):
                links.add(u)
    except:
        pass
    return links

def bfs_crawl_and_scan(starts, depth, screenshot_dir):
    visited = set()
    bfs_tree = {}
    q = []
    for s in starts:
        heapq.heappush(q, (0, s))
        bfs_tree[s] = []
    results = []
    http_executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
    while q:
        d, u = heapq.heappop(q)
        if u in visited:
            continue
        if d > depth:
            break
        visited.add(u)
        http_future = http_executor.submit(scan_target, u)
        chrome_res = scan_with_chromedriver(u, screenshot_dir)
        http_res = http_future.result()
        b1 = http_res.get("body", "")
        b2 = chrome_res.get("data", "")
        bfs_tree[u] = []
        if "error" not in http_res:
            new_links = extract_links_from_html(u, b1)
            for nl in new_links:
                if nl not in visited:
                    heapq.heappush(q, (d+1, nl))
                    if nl not in bfs_tree:
                        bfs_tree[nl] = []
                    bfs_tree[u].append(nl)
        if b2:
            new_links2 = extract_links_from_html(u, b2)
            for nl2 in new_links2:
                if nl2 not in visited:
                    heapq.heappush(q, (d+1, nl2))
                    if nl2 not in bfs_tree:
                        bfs_tree[nl2] = []
                    bfs_tree[u].append(nl2)
        c_details = http_res.get("matched_details", [])
        if chrome_res["error"]:
            c_details.append(label_entry("ChromeDriver Error","browser-based detection", chrome_res["error"]))
        else:
            c_details.extend(scan_for_vuln_patterns(b2))
        c_js = http_res.get("extracted_js_functions", [])
        if b2:
            c_js.extend(extract_js_functions(b2))
        final = {
            "url": u,
            "server": http_res.get("server", "Unknown"),
            "status_code": http_res.get("status_code", "N/A"),
            "reason": http_res.get("reason", "N/A"),
            "error": http_res.get("error", "") or chrome_res.get("error", ""),
            "matched_details": c_details,
            "extracted_js_functions": c_js
        }
        results.append(final)
    http_executor.shutdown()
    return results, bfs_tree

def write_scan_results_text(rs, filename="scan_results.txt"):
    with open(filename, "w", encoding="utf-8") as f:
        for r in rs:
            f.write(f"Server: {r.get('server','Unknown')}\nURL: {r['url']}\n")
            if "error" in r and r["error"]:
                f.write(f"  Error: {r['error']}\n")
            if r.get("matched_details"):
                for pt, tac, snip, ex, conf in r["matched_details"]:
                    f.write(f"    {pt}\n      Tactic: {tac}\n      Explanation: {ex}\n      Snippet: {snip}\n")
            if r.get("extracted_js_functions"):
                f.write("  JS Functions:\n")
                for funcdef in r["extracted_js_functions"]:
                    f.write(f"    {funcdef}\n")
            f.write("\n")

def write_scan_results_json(rs):
    ts = time.strftime("%Y%m%d_%H%M%S")
    d = f"results_{ts}"
    os.makedirs(d, exist_ok=True)
    op = os.path.join(d,"scan_results.json")
    o = []
    for r in rs:
        i = {
            "server": r.get("server","Unknown"),
            "url": r["url"],
            "status": None,
            "error": r.get("error",""),
            "detections": [],
            "extracted_js_functions": r.get("extracted_js_functions",[])
        }
        if "status_code" in r:
            i["status"] = f"{r.get('status_code','N/A')} {r.get('reason','')}"
        for pt, tac, snip, ex, conf in r["matched_details"]:
            i["detections"].append({
                "type": pt,
                "tactic": tac,
                "explanation": ex,
                "snippet": snip,
                "confidence": round(conf, 3)
            })
        o.append(i)
    with open(op,"w",encoding="utf-8") as f:
        json.dump(o, f, indent=2)

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--depth", type=int, default=2)
    args = parser.parse_args()

    screenshot_dir = os.path.join("screenshots", time.strftime("%Y%m%d_%H%M%S"))
    os.makedirs(screenshot_dir, exist_ok=True)

    results, bfs_tree = bfs_crawl_and_scan(test_sites, args.depth, screenshot_dir)
    for r in results:
        print(f"\nServer: {r.get('server','Unknown')} | {r['url']}")
        if r["error"]:
            print(f"  Error: {r['error']}")
        if r["matched_details"]:
            for pt, tactic, snippet, explanation, conf in r["matched_details"]:
                print(f"  Detected: {pt}\n    Explanation: {ex}\n    Tactic: {tactic}\n    Snippet: {snippet}")
        if r.get("extracted_js_functions"):
            print("  JS Functions:")
            for f_ in r["extracted_js_functions"]:
                print(f"   ", f_)

    with open("priority_bfs_tree.json", "w", encoding="utf-8") as f:
        json.dump(bfs_tree, f, indent=2)

    print("\nPriorityBFS Tree:")
    for node, children in bfs_tree.items():
        print(node, "->", children)

    write_scan_results_text(results, "scan_results.txt")
    write_scan_results_json(results)

if __name__ == "__main__":
    main()
