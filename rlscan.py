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
import traceback
import matplotlib.pyplot as plt
import networkx as nx
from pathlib import Path
from bs4 import BeautifulSoup
from test_sites import test_sites
import gym
from gym import spaces
import numpy as np
import socket
import ssl

"""
Adding additional vulnerability patterns and subdomain enumeration capabilities
as part of the improvements. Vulnerability analysis comments included inline.

IDOR (Insecure Direct Object Reference) can allow unauthorized users to access objects
by providing or manipulating object references (IDs) directly, bypassing authorization.
Exposed Jenkins can disclose administrative consoles. Race condition references can show
timing-based vulnerabilities. 
"""

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    import joblib
    ML_CLASSIFIER_AVAILABLE = True
except ImportError:
    ML_CLASSIFIER_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

XSS_MODEL_PATH = "xss_js_model.joblib"
SQLI_MODEL_PATH = "sql_injection_model.joblib"
MULTI_MODELS_DIR = "ml_models"
MAX_BODY_SNIPPET_LEN = 5000
ENABLE_HEADER_SCANNING = True
ENABLE_FORM_PARSING = True
CUSTOM_HEADERS = {"User-Agent":"ImprovedSecurityScanner/1.0"}

XSS_REGEXES = [
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
    "<script src=['\"]http://[^>]*?>"
]

"""
Added IDOR, Exposed Jenkins, Race Condition checks, etc. 
These checks can reveal direct object references, Jenkins console leaks, 
and suspicious patterns that indicate race conditions or concurrency flaws.
"""
VULN_PATTERNS = {
    "SQL Error": re.compile(r"(sql\s*exception|sql\s*syntax|warning.*mysql.*|unclosed\s*quotation\s*mark|microsoft\s*ole\s*db\s*provider|odbc\s*sql\s*server\s*driver|pg_query\()",re.IGNORECASE|re.DOTALL),
    "SQL Injection": re.compile(r"(\bunion\s+select\s|\bselect\s+\*\s+from\s|\bsleep\(|\b'or\s+1=1\b|\b'or\s+'a'='a\b|--|#|xp_cmdshell|information_schema)",re.IGNORECASE|re.DOTALL),
    "XSS": re.compile("|".join(XSS_REGEXES),re.IGNORECASE|re.DOTALL),
    "Directory Listing": re.compile(r"(<title>\s*index of\s*/\s*</title>|directory\s+listing\s+for)",re.IGNORECASE|re.DOTALL),
    "File Inclusion": re.compile(r"(include|require)(_once)?\s*\(.*?http://",re.IGNORECASE|re.DOTALL),
    "Server Error": re.compile(r"(internal\s+server\s+error|500\s+internal|traceback\s*\(most\s+recent\s+call\s+last\))",re.IGNORECASE|re.DOTALL),
    "Shellshock": re.compile(r"\(\)\s*\{:\;};",re.IGNORECASE|re.DOTALL),
    "Remote Code Execution": re.compile(r"(exec\(|system\(|shell_exec\(|/bin/sh|eval\(|\bpython\s+-c\s)",re.IGNORECASE|re.DOTALL),
    "LFI/RFI": re.compile(r"(etc/passwd|boot.ini|\\\\\\\\\.\\\\pipe\\\\|\\\.\\pipe\\)",re.IGNORECASE|re.DOTALL),
    "SSRF": re.compile(r"(127\.0\.0\.1|localhost|metadata\.google\.internal)",re.IGNORECASE|re.DOTALL),
    "Path Traversal": re.compile(r"(\.\./\.\./|\.\./|\.\.\\)",re.IGNORECASE|re.DOTALL),
    "Command Injection": re.compile(r"(\|\||&&|;|/bin/bash|/bin/zsh)",re.IGNORECASE|re.DOTALL),
    "WordPress Leak": re.compile(r"(wp-content|wp-includes|wp-admin)",re.IGNORECASE|re.DOTALL),
    "Java Error": re.compile(r"(java\.lang\.|exception\s+in\s+thread\s+\"main\")",re.IGNORECASE|re.DOTALL),
    "Open Redirect": re.compile(r"(=\s*https?:\/\/)",re.IGNORECASE|re.DOTALL),
    "Deserialization": re.compile(r"(java\.io\.objectinputstream|ysoserial|__proto__|constructor\.prototype)",re.IGNORECASE|re.DOTALL),
    "XXE": re.compile(r"(<!doctype\s+[^>]*\[.*<!entity\s+[^>]*system)",re.IGNORECASE|re.DOTALL),
    "File Upload": re.compile(r"(multipart/form-data.*filename=)",re.IGNORECASE|re.DOTALL),
    "Prototype Pollution": re.compile(r"(\.__proto__|object\.prototype|object\.setprototypeof)",re.IGNORECASE|re.DOTALL),
    "NoSQL Injection": re.compile(r"(db\.\w+\.find\(|\$\w+\{|{\s*\$where\s*:)",re.IGNORECASE|re.DOTALL),
    "Exposed Git Directory": re.compile(r"(\.git/HEAD|\.gitignore|\.git/config)",re.IGNORECASE|re.DOTALL),
    "Potential Secrets": re.compile(r"(aws_access_key_id|aws_secret_access_key|api_key|private_key|authorization:\s*bearer\s+[0-9a-z\-_\.]+)",re.IGNORECASE|re.DOTALL),
    "JWT Token Leak": re.compile(r"(eyjh[a-z0-9_-]*\.[a-z0-9_-]+\.[a-z0-9_-]+)",re.IGNORECASE|re.DOTALL),
    "ETC Shadow Leak": re.compile(r"/etc/shadow",re.IGNORECASE|re.DOTALL),
    "Possible Password Leak": re.compile(r"(password\s*=\s*\w+)",re.IGNORECASE|re.DOTALL),
    "CC Leak": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "CRLF Injection": re.compile(r"(\r\n|%0d%0a|%0A%0D)",re.IGNORECASE|re.DOTALL),
    "HTTP Request Smuggling": re.compile(r"(content-length:\s*\d+.*\r?\n\s*transfer-encoding:\s*chunked|transfer-encoding:\s*chunked.*\r?\n\s*content-length:\s*\d+)",re.IGNORECASE|re.DOTALL),
    "LDAP Injection": re.compile(r"(\(\w+=\*\)|\|\(\w+=\*\)|\(\w+~=\*)",re.IGNORECASE|re.DOTALL),
    "XPath Injection": re.compile(r"(/[^/]+/|\[[^\]]+\]|text\(\)=)",re.IGNORECASE|re.DOTALL),
    "Exposed S3 Bucket": re.compile(r"s3\.amazonaws\.com",re.IGNORECASE),
    "Exposed Azure Blob": re.compile(r"blob\.core\.windows\.net",re.IGNORECASE),
    "Exposed K8s Secrets": re.compile(r"kube[\s_-]*config|k8s[\s_-]*secret|kubeadm[\s_-]*token",re.IGNORECASE|re.DOTALL),
    "npm Token": re.compile(r"npm[_-]token_[a-z0-9]{36}",re.IGNORECASE|re.DOTALL),
    "GraphQL Injection": re.compile(r"(query\s*\{|\{\s*query\s*|mutation\s*\{|\{\s*mutation\s*)",re.IGNORECASE|re.DOTALL),
    "Regex DOS": re.compile(r"(\(\?[^\)]*?\)|\[[^\]]{100,}\])",re.IGNORECASE|re.DOTALL),
    "Potential WAF": re.compile(r"(cloudflare|incapsula|mod_security|sucuri\scloudproxy)",re.IGNORECASE),
    "Exposed .env File": re.compile(r"\.env(\.backup|\.\d+)?", re.IGNORECASE),
    "Exposed Environment Variable": re.compile(r"(ENV|ENVIRONMENT|SECRET_KEY|DJANGO_SECRET_KEY)=[^\s]+", re.IGNORECASE),
    "Default Credentials": re.compile(r"(admin:\s*admin|root:\s*root|test:\s*test)", re.IGNORECASE),
    "Email Leak": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.IGNORECASE),
    "Phone Number Leak": re.compile(r"\b\+?\d{1,4}[\s-]?\(?\d{1,4}?\)?[\s-]?\d{3}[\s-]?\d{4}\b"),
    "Possible SSN Leak": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "Insecure Direct Object Reference (IDOR)": re.compile(r"(user_id=\d+|account_id=\d+|profile_id=\d+)", re.IGNORECASE),
    "Exposed Jenkins Console": re.compile(r"(jenkins/manage|jenkins/script|x-jenkins)", re.IGNORECASE),
    "Race Condition": re.compile(r"(threading\.Thread|sleep\(\)|race condition|lockfile)", re.IGNORECASE)
}

HEADER_PATTERNS = {
    "Missing Security Headers": ["Content-Security-Policy","X-Content-Type-Options","X-Frame-Options","X-XSS-Protection","Strict-Transport-Security"],
    "Outdated or Insecure Server": re.compile(r"(apache/2\.2\.\d|nginx/1\.10\.\d|iis/6\.0|php/5\.2)",re.IGNORECASE)
}

VULN_EXPLANATIONS = {
    "SQL Error":"Server returned detailed database error messages revealing structure or SQL syntax issues.",
    "SQL Injection":"Possible direct injection into SQL queries, risking data exfiltration or destructive queries.",
    "XSS":"Reflected, stored, or DOM-based cross-site scripting found, potentially allowing script execution in the client.",
    "Directory Listing":"Server exposes directory contents, allowing enumeration or data leakage.",
    "File Inclusion":"Local or remote file inclusion may allow reading of sensitive files or remote code execution.",
    "Server Error":"HTTP 500 or similar errors indicating unstable or unhandled exceptions on the server side.",
    "Shellshock":"Vulnerable to Bash environment variable injection.",
    "Remote Code Execution":"Code or commands can be executed on the remote server.",
    "LFI/RFI":"Local or Remote File Inclusion vulnerability references in the response or parameters.",
    "SSRF":"Potential server-side request forgery, allowing requests to internal services.",
    "Path Traversal":"Traversal attempt or reference that may allow accessing arbitrary files on the server.",
    "Command Injection":"Executing OS commands via user input injection.",
    "WordPress Leak":"Indicates WordPress installation leakage, might reveal version or sensitive WP paths.",
    "Java Error":"Exposed Java stack trace or error logs that can reveal code structure.",
    "Open Redirect":"Redirecting users to untrusted external domains via user input.",
    "Deserialization":"Data suggests unsafe object deserialization paths, leading to code execution.",
    "XXE":"XML external entity usage, which can leak files or execute SSRF.",
    "File Upload":"Server-side file upload point can introduce malicious files if not secured.",
    "Prototype Pollution":"Manipulating JS object prototypes can compromise logic or cause RCE in some cases.",
    "NoSQL Injection":"Mongo-like or other NoSQL injection references found in the payload or response.",
    "Exposed Git Directory":".git folder or config data exposed, revealing code history or credentials.",
    "Potential Secrets":"Possible keys/tokens in the response that could be sensitive.",
    "JWT Token Leak":"JSON Web Token is exposed, risking session hijack.",
    "ETC Shadow Leak":"Direct mention or reading of /etc/shadow indicates severe file disclosure.",
    "Missing Security Headers":"Important headers not present; can open XSS, clickjacking, or MITM risk.",
    "Outdated or Insecure Server":"Server version is known to have vulnerabilities.",
    "Cookies lack 'Secure'/'HttpOnly'":"Cookies do not have secure or HTTPOnly flags, raising session hijack risk.",
    "Suspicious param name:":"Parameter name strongly suggests command, shell, or token usage.",
    "Suspicious param value in":"Parameter value suggests injection attempts or malicious content.",
    "Form uses GET with password/hidden":"Sensitive data sent in GET query, risking exposure in logs or referrers.",
    "Suspicious form fields (cmd/shell/token)":"Potential malicious or elevated function fields in forms.",
    "POST form without CSRF token":"Form lacks CSRF protection token, vulnerable to cross-site request forgery.",
    "Service Disruption":"Repeated 5xx or timeouts indicating server instability or overload.",
    "Possible Password Leak":"A direct 'password=...' mention in the response or code snippet.",
    "CC Leak":"Raw credit card number patterns in the output, indicating possible data leak.",
    "CRLF Injection":"HTTP header injection or response splitting possibility.",
    "HTTP Request Smuggling":"Conflicting Content-Length/Transfer-Encoding likely enabling request smuggling.",
    "LDAP Injection":"Injection attempt for LDAP queries.",
    "XPath Injection":"Injection attempt for XPath queries.",
    "Exposed S3 Bucket":"Open or visible AWS S3 bucket references.",
    "Exposed Azure Blob":"Open or visible Azure blob container references.",
    "Exposed K8s Secrets":"References to Kubernetes config or tokens.",
    "npm Token":"npm private access token leaked.",
    "GraphQL Injection":"Possible injection or misconfiguration in GraphQL queries.",
    "Regex DOS":"Potential catastrophic backtracking in a regex leading to DoS.",
    "CORS Misconfiguration":"Server sets overly broad Access-Control-Allow-Origin or credentials incorrectly.",
    "Insecure HTTP Methods":"Server allows potentially risky HTTP methods like PUT, DELETE, or TRACE.",
    "No explanation":"No explanation",
    "Potential WAF":"Site might be behind or protected by a WAF, or the response indicates WAF presence.",
    "ChromeDriver Error":"Error occurred while using ChromeDriver for scanning",
    "Exposed .env File":"Potentially exposed .env or backup .env file with sensitive info.",
    "Exposed Environment Variable":"Possible environment variable or secret in the response.",
    "Default Credentials":"Found default credentials patterns indicating insecure configuration.",
    "Email Leak":"Possible email address patterns found in the response.",
    "Phone Number Leak":"Possible phone number patterns found in the response.",
    "Possible SSN Leak":"Possible Social Security Number patterns found in the response.",
    "SSL Certificate Issue":"Possible issues with the certificate, such as expiration, invalid domain, or self-signed certificate that might not be trusted.",
    "Insecure Direct Object Reference (IDOR)":"Allows unauthorized access or manipulation of objects by modifying direct references (IDs).",
    "Exposed Jenkins Console":"Possible open Jenkins manage/script console or headers indicating Jenkins environment.",
    "Race Condition":"Potential concurrency/race scenario references that might lead to inconsistent state or exploit."
}

def label_entry(label,tactic,snippet,confidence=1.0):
    e = VULN_EXPLANATIONS.get(label,"No explanation")
    return (label,tactic,snippet,e,confidence)

MULTI_VULN_SAMPLES = {
    "SQL Error":(["syntax error near 'FROM'","ODBC SQL server driver failed","error in your SQL syntax"],["normal query","sql logging enabled"]),
    "SQL Injection":(["UNION SELECT pass FROM users","' OR '1'='1","xp_cmdshell"],["SELECT id, name FROM product","UPDATE user set pass=?"]),
    "XSS":(["<script>alert('X')</script>","<img src=x onerror=alert(1)>","<svg onload=alert('svgxss')>"],["function hello(){}","var cleanVar=5;"]),
    "Directory Listing":(["<title>Index of /</title>"],["normal html"]),
    "File Inclusion":(["require(http://evil.com)","include(http://hack.site)"],["normal require","safe block"]),
    "Server Error":(["internal server error","Traceback (most recent call last)"],["ok response"]),
    "Shellshock":(["() { :;}; echo exploit"],["bash script safe"]),
    "Remote Code Execution":(["exec(","shell_exec(","system("],["safe()"]),
    "LFI/RFI":(["etc/passwd","boot.ini","../../etc/passwd"],["safe file read"]),
    "SSRF":(["127.0.0.1","localhost","metadata.google.internal"],["remote api call"]),
    "Path Traversal":(["../etc/passwd"],["safe path usage"]),
    "Command Injection":(["|| ls","&& whoami","; uname -a"],["normal usage"]),
    "WordPress Leak":(["wp-content","wp-admin"],["mention WP"]),
    "Java Error":(["java.lang.NullPointerException"],["normal logs"]),
    "Open Redirect":(["=http://","=https://"],["redirect internal"]),
    "Deserialization":(["java.io.ObjectInputStream","__proto__","ysoserial"],["normal data"]),
    "XXE":(["<!DOCTYPE foo [<!ENTITY"],["normal xml"]),
    "File Upload":(["multipart/form-data","filename="],["safe form"]),
    "Prototype Pollution":([".__proto__","Object.setPrototypeOf"],["normal js"]),
    "NoSQL Injection":(["db.users.find(","$where"],["normal nosql"]),
    "Exposed Git Directory":([".git/HEAD",".gitignore",".git/config"],["repo mention"]),
    "Potential Secrets":(["aws_secret_access_key","api_key","authorization: bearer 123abc"],["key param masked"]),
    "JWT Token Leak":(["eyJh.eyJ"],["normal token usage"]),
    "ETC Shadow Leak":(["/etc/shadow"],["safe reference"]),
    "Missing Security Headers":(["lack of csp, x-frame"],["csp present"]),
    "Outdated or Insecure Server":(["apache/2.2.14","nginx/1.10.3"],["apache/2.4","nginx/1.22"]),
    "Cookies lack 'Secure'/'HttpOnly'":(["set-cookie: sessionid=abc123"],["set-cookie: secure; httponly"]),
    "Suspicious param name:":(["cmd","shell","token"],["id","name"]),
    "Suspicious param value in":(["<script>","' or 1=1","%0d%0a"],["normal"]),
    "Form uses GET with password/hidden":(["<form method='get'><input type='password'>"],["<form method='post'>"]),
    "Suspicious form fields (cmd/shell/token)":(["name='cmd'"],["name='username'"]),
    "POST form without CSRF token":(["<form method='post'>"],["<form method='post'><input name='csrf'>"]),
    "Service Disruption":(["503 service unavailable","502 bad gateway"],["200 ok"]),
    "Possible Password Leak":(["password=secret"],["pwd=masked"]),
    "CC Leak":(["4111 1111 1111 1111"],["1111"]),
    "CRLF Injection":(["%0d%0a","\\r\\n"],["normal line break"]),
    "HTTP Request Smuggling":(["transfer-encoding: chunked\r\ncontent-length: 100"],["normal headers"]),
    "LDAP Injection":(["(cn=*)","|(objectClass=*)","(uid=*)"],["(cn=John)","(&(objectClass=person)(cn=John))"]),
    "XPath Injection":(["/users/user","text()='secret'","[contains(text(),'test')]"],["normal xml","legitimate xpath"]),
    "Exposed S3 Bucket":(["mybucket.s3.amazonaws.com","bucket.s3.amazonaws.com"],["normal usage"]),
    "Exposed Azure Blob":([".blob.core.windows.net"],["safe azure usage"]),
    "Exposed K8s Secrets":(["kubeconfig","k8s_secret","kubeadm token"],["kube cluster safe"]),
    "npm Token":(["npm_token_123456789012345678901234567890123456"],["safe usage"]),
    "GraphQL Injection":(["query { user(id:\"1\")","mutation { createUser"],["safe gql usage"]),
    "Regex DOS": (["(a|aa|aaa)*","(x|y|z)+{100,}"],["safe patterns"]),
    "Potential WAF":(["cloudflare","incapsula","mod_security"],["none"]),
    "Exposed .env File":([".env",".env.backup"],[""]),
    "Exposed Environment Variable":(["ENV=production","SECRET_KEY=abc123"],[""]),
    "Default Credentials":(["admin:admin","root:root","test:test"],[""])
}

CVE_DB = {
    "apache/2.2.14":"Possible CVEs: CVE-2010-0408, CVE-2010-1452",
    "nginx/1.10.3":"Possible CVEs: CVE-2017-7529, CVE-2019-20372"
}

"""
New function to do simple subdomain enumeration for domain expansions.
This further improves scanning capabilities by searching potential subdomains.
"""
def find_subdomains(domain, subdomains_list=["www","dev","test","admin"]):
    found_subdomains = []
    for sub in subdomains_list:
        potential = f"{sub}.{domain}"
        try:
            socket.gethostbyname(potential)
            found_subdomains.append(potential)
        except:
            pass
    return found_subdomains

def train_base_ml_models():
    if not ML_CLASSIFIER_AVAILABLE:
        return
    if not os.path.isfile(XSS_MODEL_PATH):
        sus_js = [
            "<script>alert('Hacked!')</script>",
            "javascript:alert('XSS')",
            "onerror=alert(document.cookie)",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert('svgxss')>",
            "<script src='http://evil.com/x.js'></script>"
        ]
        ben_js = [
            "function greetUser(name) {}",
            "var x=5; if(x>2){x++;}",
            "document.getElementById('x').innerText='Safe';",
            "function normalFunc(){}"
        ]
        X_data = sus_js + ben_js
        y_data = [1]*len(sus_js) + [0]*len(ben_js)
        vec = TfidfVectorizer(ngram_range=(1,2),max_features=500)
        X_vec = vec.fit_transform(X_data)
        clf = LogisticRegression()
        clf.fit(X_vec,y_data)
        joblib.dump({"vectorizer":vec,"classifier":clf},XSS_MODEL_PATH)
    if not os.path.isfile(SQLI_MODEL_PATH):
        sus_sql = [
            "' OR '1'='1",
            "UNION SELECT username, password FROM users",
            "' OR 'a'='a",
            "SELECT * FROM table WHERE id='",
            "' DROP TABLE users --",
            "xp_cmdshell",
            "OR 1=1 LIMIT 1"
        ]
        ben_sql = [
            "SELECT id, name FROM products",
            "INSERT INTO users VALUES ('test','pass')",
            "UPDATE accounts SET balance=500 WHERE userid=1",
            "CREATE TABLE logs (entry TEXT)"
        ]
        X_data = sus_sql + ben_sql
        y_data = [1]*len(sus_sql) + [0]*len(ben_sql)
        vec = TfidfVectorizer(ngram_range=(1,2),max_features=500)
        X_vec = vec.fit_transform(X_data)
        clf = LogisticRegression()
        clf.fit(X_vec,y_data)
        joblib.dump({"vectorizer":vec,"classifier":clf},SQLI_MODEL_PATH)

def train_all_vulnerability_models():
    if not ML_CLASSIFIER_AVAILABLE:
        return
    if not os.path.isdir(MULTI_MODELS_DIR):
        os.makedirs(MULTI_MODELS_DIR)
    for vuln_name,(suspicious,benign) in MULTI_VULN_SAMPLES.items():
        mp = os.path.join(MULTI_MODELS_DIR,f"{vuln_name.replace(' ','_').replace(':','').replace('/','_')}.joblib")
        if not os.path.isfile(mp):
            X_data = suspicious + benign
            y_data = [1]*len(suspicious) + [0]*len(benign)
            vec = TfidfVectorizer(ngram_range=(1,2),max_features=300)
            X_vec = vec.fit_transform(X_data)
            clf = LogisticRegression()
            clf.fit(X_vec,y_data)
            joblib.dump({"vectorizer":vec,"classifier":clf},mp)

def load_ml_model(path):
    if not ML_CLASSIFIER_AVAILABLE or not os.path.isfile(path):
        return None
    try:
        return joblib.load(path)
    except:
        return None

def ml_detection_confidence(snippet,model):
    if not model:
        return (0.0,False)
    v = model["vectorizer"]
    c = model["classifier"]
    X = v.transform([snippet])
    prob = c.predict_proba(X)[0][1]
    return (prob,prob>=0.5)

def normalize_and_decode(text):
    if not text:
        return text
    d1 = urllib.parse.unquote(text)
    d2 = html.unescape(d1)
    return d2.lower()

def multiple_decode_passes(text,passes=3):
    c = text
    for _ in range(passes):
        c = urllib.parse.unquote(c)
        c = html.unescape(c)
    return c.lower()

def scan_for_vuln_patterns(snippet):
    f = []
    n = normalize_and_decode(snippet)
    m = multiple_decode_passes(snippet,2)
    for label,pattern in VULN_PATTERNS.items():
        for match in pattern.finditer(n):
            s = match.group(0)
            if len(s)>200: s = s[:200]+"..."
            f.append(label_entry(label,"pattern-based detection",s))
        for match in pattern.finditer(m):
            s = match.group(0)
            if len(s)>200: s = s[:200]+"..."
            f.append(label_entry(label,"pattern-based detection",s))
    return list(set(f))

def dom_based_xss_detection(ht):
    r = []
    try:
        soup = BeautifulSoup(ht,"lxml")
    except:
        return r
    for s in soup.find_all("script"):
        if s.string and re.search(r"(alert|document\.cookie|<script)",s.string,re.IGNORECASE):
            sn = s.string.strip()
            if len(sn)>200: sn = sn[:200]+"..."
            r.append(label_entry("XSS","DOM-based detection",sn))
    for tag in soup.find_all():
        for attr in tag.attrs:
            if attr.lower().startswith("on"):
                a = f"{attr}={tag.attrs[attr]}"
                r.append(label_entry("XSS","DOM-based detection",a))
    return r

def scan_response_headers(headers):
    f = []
    if not headers:
        return f
    for h in HEADER_PATTERNS["Missing Security Headers"]:
        if h.lower() not in [k.lower() for k in headers.keys()]:
            f.append(label_entry("Missing Security Headers","header-based detection",h))
    srv = headers.get("Server","")
    p = HEADER_PATTERNS["Outdated or Insecure Server"]
    if p.search(srv):
        f.append(label_entry("Outdated or Insecure Server","header-based detection",srv))
        srv_lower = srv.lower()
        if srv_lower in CVE_DB:
            f.append(label_entry("Outdated or Insecure Server","possible-cve-info",CVE_DB[srv_lower]))
    sc = headers.get("Set-Cookie","")
    if sc and ("secure" not in sc.lower() or "httponly" not in sc.lower()):
        f.append(label_entry("Cookies lack 'Secure'/'HttpOnly'","header-based detection",sc))
    return f

def parse_suspicious_forms(ht):
    r = []
    t = normalize_and_decode(ht)
    form_p = re.compile(r"<form\b.*?</form>",re.IGNORECASE|re.DOTALL)
    fs = form_p.findall(t)
    for f_ in fs:
        mm = re.search(r"method\s*=\s*(['\"])(.*?)\1",f_,re.IGNORECASE|re.DOTALL)
        c = f_[:200]+"..." if len(f_)>200 else f_
        if mm and mm.group(2).lower()=="get":
            if re.search(r"type\s*=\s*(['\"])(password|hidden)\1",f_,re.IGNORECASE):
                r.append(label_entry("Form uses GET with password/hidden","form-based detection",c))
        if re.search(r"name\s*=\s*(['\"])(cmd|shell|token)\1",f_,re.IGNORECASE):
            r.append(label_entry("Suspicious form fields (cmd/shell/token)","form-based detection",c))
        if mm and mm.group(2).lower()=="post" and not re.search(r"name\s*=\s*(['\"])(csrf|csrf_token)\1",f_,re.IGNORECASE):
            r.append(label_entry("POST form without CSRF token","form-based detection",c))
    return r

def analyze_query_params(url):
    from urllib.parse import urlparse,parse_qs
    f = []
    u = urlparse(url)
    qs = parse_qs(u.query)
    for p,vals in qs.items():
        dp = normalize_and_decode(p)
        if re.search(r"(cmd|exec|shell|script|token|redir|redirect)",dp,re.IGNORECASE):
            f.append(label_entry("Suspicious param name:","query-param detection",p))
        for v in vals:
            dv = normalize_and_decode(v)
            if re.search(r"(<>|<script>|' or 1=1|../../|jsessionid=|%0a|%0d)",dv,re.IGNORECASE):
                f.append(label_entry("Suspicious param value in","query-param detection",f"{p}={v}"))
    return f

class InjectionsEnv(gym.Env):
    def __init__(self):
        super(InjectionsEnv, self).__init__()
        self.payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "; ls;",
            "&& cat /etc/passwd",
            "<img src=x onerror=alert(2)>",
            "'; DROP TABLE users; --",
            "|| ping -c 4 127.0.0.1 ||"
        ]
        self.action_space = spaces.Discrete(len(self.payloads))
        self.observation_space = spaces.Discrete(1)
        self.state = 0
        self.success_counts = {p:0 for p in self.payloads}
        self.total_counts = {p:0 for p in self.payloads}
        self.new_payloads_pool = [
            "' and 'x'='x",
            "<svg onload=alert('newXSS')>",
            "OR 1=1 -- Test"
        ]

    def reset(self):
        self.state = 0
        return self.state

    def step(self, action):
        reward = random.random()
        done = True
        return self.state, reward, done, {}

    def update_payloads(self, successes, failures):
        for s in successes:
            self.success_counts[s] += 1
            self.total_counts[s] += 1
        for f in failures:
            if f not in self.total_counts:
                self.total_counts[f] = 0
            self.total_counts[f] += 1
        to_remove = []
        for p in self.payloads:
            if self.total_counts[p] >= 5:
                ratio = self.success_counts[p] / float(self.total_counts[p])
                if ratio < 0.2:
                    to_remove.append(p)
        for r in to_remove:
            if r in self.payloads:
                self.payloads.remove(r)
                del self.success_counts[r]
                del self.total_counts[r]
        if random.random() < 0.3 and self.new_payloads_pool:
            new_p = random.choice(self.new_payloads_pool)
            if new_p not in self.payloads:
                self.payloads.append(new_p)
                self.success_counts[new_p] = 0
                self.total_counts[new_p] = 0
        self.action_space = spaces.Discrete(len(self.payloads))

def run_mcts_for_injections(env,iterations=10):
    best_action = 0
    best_q = -1
    for a in range(env.action_space.n):
        q_value = 0
        for _ in range(iterations):
            _, r, _, _ = env.step(a)
            q_value += r
        avg_q = q_value / iterations
        if avg_q > best_q:
            best_q = avg_q
            best_action = a
    return env.payloads[best_action]

def fuzz_injection_tests(url):
    fs = []
    success_injections = []
    failed_injections = []
    env = InjectionsEnv()
    for _ in range(len(env.payloads)):
        injection = run_mcts_for_injections(env,5)
        injection_url = f"{url}?inj={urllib.parse.quote(injection)}"
        try:
            r = requests.get(injection_url,timeout=3,headers=CUSTOM_HEADERS)
            new_matches = scan_for_vuln_patterns(r.text)
            fs.extend(new_matches)
            if new_matches:
                success_injections.append(injection)
            else:
                failed_injections.append(injection)
        except:
            failed_injections.append(injection)
        env.update_payloads(success_injections, failed_injections)
    return fs, {"success": success_injections, "fail": failed_injections}

def fuzz_injection_tests_post(url):
    fs = []
    success_injections = []
    failed_injections = []
    env = InjectionsEnv()
    for _ in range(len(env.payloads)):
        injection = run_mcts_for_injections(env,5)
        try:
            r = requests.post(url, data={"inj": injection}, timeout=3, headers=CUSTOM_HEADERS)
            new_matches = scan_for_vuln_patterns(r.text)
            fs.extend(new_matches)
            if new_matches:
                success_injections.append(injection)
            else:
                failed_injections.append(injection)
        except:
            failed_injections.append(injection)
        env.update_payloads(success_injections, failed_injections)
    return fs, {"success_post": success_injections, "fail_post": failed_injections}

def repeated_disruption_test(url,attempts=3):
    f = []
    for _ in range(attempts):
        try:
            r = requests.get(url,timeout=3,headers=CUSTOM_HEADERS)
            if r.status_code>=500:
                f.append(label_entry("Service Disruption","frequent-request detection",str(r.status_code)))
        except:
            f.append(label_entry("Service Disruption","frequent-request detection","Exception"))
    try:
        r_head = requests.head(url, timeout=3, headers=CUSTOM_HEADERS)
        if r_head.status_code >= 500:
            f.append(label_entry("Service Disruption","head-request detection",str(r_head.status_code)))
    except:
        f.append(label_entry("Service Disruption","head-request detection","Exception"))
    return f

def extract_js_functions(ht):
    d = []
    sc = re.findall(r"<script[^>]*>(.*?)</script>",ht,re.IGNORECASE|re.DOTALL)
    for sb in sc:
        m = re.findall(r"(function\s+[a-zA-Z0-9_$]+\s*\([^)]*\)\s*\{.*?\})",sb,re.DOTALL)
        for mm in m:
            if len(mm)>400: mm = mm[:400]+"..."
            d.append(mm.strip())
    return d

def check_cors_misconfiguration(url):
    findings = []
    custom_origin = {"Origin":"https://evil.com"}
    try:
        r = requests.get(url, headers={**CUSTOM_HEADERS, **custom_origin}, timeout=5)
        if "Access-Control-Allow-Origin" in r.headers:
            acao = r.headers["Access-Control-Allow-Origin"]
            if acao.strip() == "*" or acao.strip() == "https://evil.com":
                credentials = r.headers.get("Access-Control-Allow-Credentials","")
                snip = f"Allow-Origin:{acao}; Allow-Credentials:{credentials}"
                findings.append(label_entry("CORS Misconfiguration","cors-detection",snip))
    except:
        pass
    return findings

def check_insecure_http_methods(url):
    findings = []
    try:
        r = requests.options(url, headers=CUSTOM_HEADERS, timeout=5)
        if "Allow" in r.headers:
            allowed = r.headers["Allow"].upper()
            if any(m in allowed for m in ["PUT","DELETE","TRACE"]):
                snippet = f"Methods allowed: {r.headers['Allow']}"
                findings.append(label_entry("Insecure HTTP Methods","method-detection",snippet))
    except:
        pass
    return findings

def check_robots_txt(url):
    findings = []
    domain = urllib.parse.urlsplit(url).netloc
    if not domain:
        return findings
    robots_url = f"https://{domain}/robots.txt"
    try:
        rr = requests.get(robots_url, headers=CUSTOM_HEADERS, timeout=3)
        if rr.status_code == 200:
            lines = rr.text.splitlines()
            for line in lines:
                if line.lower().startswith("disallow:") or "admin" in line.lower() or "cgi-bin" in line.lower() or "wp-admin" in line.lower() or "secret" in line.lower():
                    snippet = line.strip()
                    if len(snippet) > 200: snippet = snippet[:200] + "..."
                    findings.append(label_entry("Potential sensitive path from robots.txt","robots-txt detection",snippet))
    except:
        pass
    return findings

def check_ssl_certificate(url):
    results = []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return results
    hostname = parsed.netloc.split(":")[0]
    port = 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    results.append(label_entry("SSL Certificate Issue","ssl-check","No certificate returned"))
                    return results
                subject = cert.get('subject',[])
                issuer = cert.get('issuer',[])
                notAfter = cert.get('notAfter','')
                notBefore = cert.get('notBefore','')
                if not notAfter or not notBefore:
                    results.append(label_entry("SSL Certificate Issue","ssl-check","Missing certificate date fields"))
                    return results
                try:
                    expires = time.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                    if time.mktime(expires) < time.time():
                        results.append(label_entry("SSL Certificate Issue","ssl-check",f"Certificate expired on {notAfter}"))
                except:
                    results.append(label_entry("SSL Certificate Issue","ssl-check",f"Cannot parse notAfter={notAfter}"))
                try:
                    begins = time.strptime(notBefore, "%b %d %H:%M:%S %Y %Z")
                    if time.mktime(begins) > time.time():
                        results.append(label_entry("SSL Certificate Issue","ssl-check",f"Certificate not yet valid until {notBefore}"))
                except:
                    results.append(label_entry("SSL Certificate Issue","ssl-check",f"Cannot parse notBefore={notBefore}"))
                if subject == issuer:
                    results.append(label_entry("SSL Certificate Issue","ssl-check","Self-signed certificate"))
    except Exception as e:
        results.append(label_entry("SSL Certificate Issue","ssl-check",f"Error verifying certificate: {str(e)}"))
    return results

def scan_target(url):
    ds = analyze_query_params(url)
    injection_findings_get, injection_outcomes_get = fuzz_injection_tests(url)
    injection_findings_post, injection_outcomes_post = fuzz_injection_tests_post(url)
    ds.extend(injection_findings_get)
    ds.extend(injection_findings_post)
    ds.extend(repeated_disruption_test(url))
    cors_findings = check_cors_misconfiguration(url)
    ds.extend(cors_findings)
    method_findings = check_insecure_http_methods(url)
    ds.extend(method_findings)
    robots_findings = check_robots_txt(url)
    ds.extend(robots_findings)
    try:
        r = requests.get(url,timeout=5,headers=CUSTOM_HEADERS)
        b = r.text[:MAX_BODY_SNIPPET_LEN]
        p_tags = scan_for_vuln_patterns(b)
        h_tags = scan_response_headers(r.headers) if ENABLE_HEADER_SCANNING else []
        f_tags = parse_suspicious_forms(b) if ENABLE_FORM_PARSING else []
        d_tags = dom_based_xss_detection(b)
        ml_tags = []
        if ML_CLASSIFIER_AVAILABLE:
            xm = load_ml_model(XSS_MODEL_PATH)
            sm = load_ml_model(SQLI_MODEL_PATH)
            if xm:
                scr_pat = re.compile(r"<script\b.*?>(.*?)</script>",re.IGNORECASE|re.DOTALL)
                for s_ in scr_pat.findall(b):
                    prob,pred = ml_detection_confidence(s_,xm)
                    if pred:
                        sn = s_.strip()
                        if len(sn)>200: sn = sn[:200]+"..."
                        ml_tags.append(label_entry("XSS",f"ML-based detection (score={prob:.3f})",sn,prob))
            if sm:
                prob,pred = ml_detection_confidence(b,sm)
                if pred:
                    sn = b[:200]+"..." if len(b)>200 else b
                    ml_tags.append(label_entry("SQL Injection",f"ML-based detection (score={prob:.3f})",sn,prob))
            for vn in MULTI_VULN_SAMPLES.keys():
                mp = os.path.join(MULTI_MODELS_DIR,f"{vn.replace(' ','_').replace(':','').replace('/','_')}.joblib")
                mm = load_ml_model(mp)
                if mm:
                    prob,pred = ml_detection_confidence(b,mm)
                    if pred:
                        sn = b[:200]+"..." if len(b)>200 else b
                        ml_tags.append(label_entry(vn,f"ML-based detection (score={prob:.3f})",sn,prob))
        all_tags = ds + p_tags + h_tags + f_tags + d_tags + ml_tags
        funcs = extract_js_functions(r.text)
        return {
            "url":url,
            "status_code":r.status_code,
            "reason":r.reason,
            "server":r.headers.get("Server","Unknown"),
            "matched_details":all_tags,
            "extracted_js_functions":funcs,
            "body":r.text,
            "injection_results": {
                "get": injection_outcomes_get,
                "post": injection_outcomes_post
            }
        }
    except Exception as e:
        return {
            "url":url,
            "error":str(e),
            "matched_details":ds,
            "server":"Unknown",
            "extracted_js_functions":[],
            "body":"",
            "injection_results": {
                "get": injection_outcomes_get,
                "post": injection_outcomes_post
            }
        }

def write_scan_results_text(rs,filename="scan_results.txt"):
    with open(filename,"w",encoding="utf-8") as f:
        for r in rs:
            f.write(f"Server causing detection: {r.get('server','Unknown')}\n")
            f.write(f"URL: {r['url']}\n")
            if "error" in r:
                f.write(f"  Error: {r['error']}\n")
                for pt,tac,snip,ex,conf in r["matched_details"]:
                    f.write(f"    {pt}\n      Tactic: {tac}\n      Explanation: {ex}\n      Snippet: {snip}\n")
            else:
                f.write(f"  Status: {r['status_code']} {r['reason']}\n")
                if r["matched_details"]:
                    for pt,tac,snip,ex,conf in r["matched_details"]:
                        f.write(f"    {pt}\n      Tactic: {tac}\n      Explanation: {ex}\n      Snippet: {snip}\n")
            f.write("  Injection Test Details:\n")
            g = r["injection_results"].get("get",{})
            p = r["injection_results"].get("post",{})
            success_injs_get = g.get("success",[])
            fail_injs_get = g.get("fail",[])
            success_injs_post = p.get("success_post",[])
            fail_injs_post = p.get("fail_post",[])
            f.write(f"    Successful GET Injections ({len(success_injs_get)}): {success_injs_get}\n")
            f.write("      Meaning: GET payloads that triggered detection.\n")
            f.write(f"    Failed GET Injections ({len(fail_injs_get)}): {fail_injs_get}\n")
            f.write("      Meaning: GET payloads that did not produce notable issues.\n")
            f.write(f"    Successful POST Injections ({len(success_injs_post)}): {success_injs_post}\n")
            f.write("      Meaning: POST payloads that triggered detection.\n")
            f.write(f"    Failed POST Injections ({len(fail_injs_post)}): {fail_injs_post}\n")
            f.write("      Meaning: POST payloads that did not produce notable issues.\n")
            if r.get("extracted_js_functions"):
                f.write("  JS Functions:\n")
                for funcdef in r["extracted_js_functions"]:
                    f.write(f"    {funcdef}\n")
            f.write("\n")

def write_scan_results_json(rs):
    ts = time.strftime("%Y%m%d_%H%M%S")
    d = f"results_{ts}"
    try:
        os.makedirs(d,exist_ok=True)
    except:
        d="."
    op = os.path.join(d,"scan_results.json")
    o = []
    for r in rs:
        i = {
            "server":r.get("server","Unknown"),
            "url":r["url"],
            "status":None,
            "error":r.get("error",""),
            "detections":[],
            "extracted_js_functions":r.get("extracted_js_functions",[]),
            "injection_tests": r.get("injection_results",{})
        }
        if "status_code" in r:
            i["status"] = f"{r.get('status_code','N/A')} {r.get('reason','')}"
        for pt,tac,snip,ex,conf in r["matched_details"]:
            i["detections"].append({
                "type":pt,"tactic":tac,"explanation":ex,"snippet":snip,"confidence":round(conf,3)
            })
        o.append(i)
    with open(op,"w",encoding="utf-8") as f:
        json.dump(o,f,indent=2)

def extract_links_from_html(url,html_text):
    links = set()
    try:
        soup = BeautifulSoup(html_text,"lxml")
        for a in soup.find_all("a",href=True):
            u = urllib.parse.urljoin(url,a["href"])
            if u.startswith("http"):
                links.add(u)
    except:
        pass
    return links

def scan_with_chromedriver(url):
    if not SELENIUM_AVAILABLE:
        return {"url":url,"error":"Selenium not available","data":"","found_flags":[]}
    try:
        o = Options()
        o.add_argument("--headless=new")
        d = webdriver.Chrome(options=o)
        d.get(url)
        found_flags = []
        try:
            forms = d.find_elements(By.TAG_NAME, "form")
            for form in forms:
                inputs = form.find_elements(By.TAG_NAME, "input")
                for inp in inputs:
                    try:
                        inp.send_keys("CTF_INJECTION_PAYLOAD")
                    except:
                        pass
                try:
                    form.submit()
                    page_source_after_submit = d.page_source
                    matches = re.findall(r"(CTF\{.*?\})", page_source_after_submit, re.IGNORECASE)
                    if matches:
                        found_flags.extend(matches)
                except:
                    pass
        except:
            pass
        c = d.page_source
        matches_global = re.findall(r"(CTF\{.*?\})", c, re.IGNORECASE)
        if matches_global:
            found_flags.extend(matches_global)
        d.quit()
        return {"url":url,"error":"","data":c,"found_flags":list(set(found_flags))}
    except Exception as e:
        error_details = traceback.format_exc()
        return {"url":url,"error":f"{str(e)}\nTraceback:\n{error_details}","data":"","found_flags":[]}

"""
Priority BFS improved to also do a quick subdomain scan at each domain level 
to expand potential target coverage drastically.
"""
def priority_bfs_crawl_and_scan(starts,max_depth=20):
    visited = set()
    q = []
    depth_map = {}
    G = nx.DiGraph()
    for s in starts:
        heapq.heappush(q,(0,s))
        depth_map[s] = 0
        G.add_node(s,depth=0)
    results = []
    http_executor = concurrent.futures.ThreadPoolExecutor(max_workers=50)
    bot_executor = concurrent.futures.ThreadPoolExecutor(max_workers=50)
    ssl_executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)

    while q:
        d,u = heapq.heappop(q)
        print(f"PriorityBFS Depth: {d}")
        print(f"Full URL: {u}")
        print("Details: scanning target, scanning with chromedriver, checking SSL, extracting links, enumerating subdomains.")
        if u in visited:
            continue
        if d>max_depth:
            break
        visited.add(u)

        # Subdomain enumeration
        domain_part = urllib.parse.urlsplit(u).netloc
        sub_enumeration = find_subdomains(domain_part)
        for subd in sub_enumeration:
            potential_url = f"http://{subd}"
            if potential_url not in visited:
                heapq.heappush(q,(d+1,potential_url))
                depth_map[potential_url] = d+1
                G.add_node(potential_url,depth=d+1)
                G.add_edge(u,potential_url)

        f1 = http_executor.submit(scan_target,u)
        f2 = bot_executor.submit(scan_with_chromedriver,u)
        f3 = ssl_executor.submit(check_ssl_certificate,u)

        r1 = f1.result()
        r2 = f2.result()
        r3 = f3.result()

        body1 = r1["body"] if "body" in r1 else ""
        body2 = r2["data"] if "data" in r2 else ""

        if "error" not in r1:
            new_links = extract_links_from_html(u,body1)
            for nl in new_links:
                if nl not in visited:
                    heapq.heappush(q,(d+1,nl))
                    depth_map[nl] = d+1
                    G.add_node(nl,depth=d+1)
                    G.add_edge(u,nl)
        if body2:
            new_links2 = extract_links_from_html(u,body2)
            for nl2 in new_links2:
                if nl2 not in visited:
                    heapq.heappush(q,(d+1,nl2))
                    depth_map[nl2] = d+1
                    G.add_node(nl2,depth=d+1)
                    G.add_edge(u,nl2)

        combined_details = r1["matched_details"] if "matched_details" in r1 else []
        combined_details.extend(r3)
        if r2["error"]:
            combined_details.append(label_entry("ChromeDriver Error","browser-based detection",r2["error"]))
        else:
            combined_details.extend(scan_for_vuln_patterns(body2))

        combined_js = r1.get("extracted_js_functions",[])
        if body2:
            combined_js.extend(extract_js_functions(body2))

        final = {
            "url":u,
            "server":r1.get("server","Unknown"),
            "status_code":r1.get("status_code","N/A"),
            "reason":r1.get("reason","N/A"),
            "error":r1.get("error","") or r2.get("error",""),
            "matched_details":combined_details,
            "extracted_js_functions":combined_js,
            "found_flags": r2.get("found_flags",[]),
            "injection_results": r1.get("injection_results",{})
        }
        results.append(final)

    http_executor.shutdown()
    bot_executor.shutdown()
    ssl_executor.shutdown()

    max_d = max(depth_map.values()) if depth_map else 0
    if max_d > max_depth:
        max_d = max_depth
    for layer in range(max_d+1):
        layer_nodes = [n for n,data in G.nodes(data=True) if data.get('depth') == layer]
        subG = G.subgraph(layer_nodes)
        plt.figure(figsize=(8,6))
        pos = nx.spring_layout(subG, seed=42)
        nx.draw_networkx(subG, pos, with_labels=True)
        plt.title(f"Layer {layer}")
        plt.show()

    return results

def main():
    sys.stdout.reconfigure(line_buffering=True)
    train_base_ml_models()
    train_all_vulnerability_models()
    user_depth = 3
    if len(sys.argv) > 1:
        try:
            user_depth = int(sys.argv[1])
        except:
            pass
    all_results = priority_bfs_crawl_and_scan(test_sites,user_depth)
    for r in all_results:
        print(f"\nServer: {r.get('server','Unknown')} | {r['url']}")
        if "error" in r and r["error"]:
            print(f"  Error: {r['error']}")
        for pt,tactic,snippet,explanation,conf in r["matched_details"]:
            print(f"  Detected: {pt}\n    Explanation: {explanation}\n    Tactic: {tactic}\n    Confidence: {conf}\n    Snippet: {snippet}")
        g_res = r["injection_results"].get("get",{})
        p_res = r["injection_results"].get("post",{})
        sg = g_res.get("success",[])
        fg = g_res.get("fail",[])
        sp = p_res.get("success_post",[])
        fp = p_res.get("fail_post",[])
        print(f"  GET Injections Succeeded ({len(sg)}): {sg}")
        print(f"  GET Injections Failed ({len(fg)}): {fg}")
        print(f"  POST Injections Succeeded ({len(sp)}): {sp}")
        print(f"  POST Injections Failed ({len(fp)}): {fp}")
        if r.get("extracted_js_functions"):
            print("  Extracted JS Functions:")
            for f_ in r["extracted_js_functions"]:
                print(f"    {f_}")
        if r.get("found_flags"):
            print("  Found Flags:")
            for flg in r["found_flags"]:
                print(f"    {flg}")
    write_scan_results_text(all_results,"scan_results.txt")
    write_scan_results_json(all_results)

if __name__=="__main__":
    main()