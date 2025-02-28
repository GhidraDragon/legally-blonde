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
from pathlib import Path
from bs4 import BeautifulSoup
from test_sites import test_sites

import tensorflow as tf
import gym

import matplotlib.pyplot as plt
import networkx as nx

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

from keras.saving import register_keras_serializable

print("[INFO] Loading constants and patterns...")
XSS_MODEL_PATH = "xss_js_model.keras"
SQLI_MODEL_PATH = "sql_injection_model.keras"
MULTI_MODELS_DIR = "ml_models_tf"
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
    r"<script src=['\"]http://[^>]*?>"
]

VULN_PATTERNS = {
    "SQL Error":re.compile(r"(sql\s*exception|sql\s*syntax|warning.*mysql.*|unclosed\s*quotation\s*mark|microsoft\s*ole\s*db\s*provider|odbc\s*sql\s*server\s*driver|pg_query\()",re.IGNORECASE|re.DOTALL),
    "SQL Injection":re.compile(r"(\bunion\s+select\s|\bselect\s+\*\s+from\s|\bsleep\(|\b'or\s+1=1\b|\b'or\s+'a'='a\b|--|#|xp_cmdshell|information_schema)",re.IGNORECASE|re.DOTALL),
    "XSS":re.compile("|".join(XSS_REGEXES),re.IGNORECASE|re.DOTALL),
    "Directory Listing":re.compile(r"(<title>\s*index of\s*/\s*</title>|directory\s+listing\s+for)",re.IGNORECASE|re.DOTALL),
    "File Inclusion":re.compile(r"(include|require)(_once)?\s*\(.*?http://",re.IGNORECASE|re.DOTALL),
    "Server Error":re.compile(r"(internal\s+server\s+error|500\s+internal|traceback\s*\(most\s+recent\s+call\s+last\))",re.IGNORECASE|re.DOTALL),
    "Shellshock":re.compile(r"\(\)\s*\{:\;};",re.IGNORECASE|re.DOTALL),
    "Remote Code Execution":re.compile(r"(exec\(|system\(|shell_exec\(|/bin/sh|eval\(|\bpython\s+-c\s)",re.IGNORECASE|re.DOTALL),
    "LFI/RFI":re.compile(r"(etc/passwd|boot.ini|\\\\\\\\\.\\\\pipe\\\\|\\\.\\pipe\\)",re.IGNORECASE|re.DOTALL),
    "SSRF":re.compile(r"(127\.0\.0\.1|localhost|metadata\.google\.internal)",re.IGNORECASE|re.DOTALL),
    "Path Traversal":re.compile(r"(\.\./\.\./|\.\./|\.\.\\)",re.IGNORECASE|re.DOTALL),
    "Command Injection":re.compile(r"(\|\||&&|;|/bin/bash|/bin/zsh)",re.IGNORECASE|re.DOTALL),
    "WordPress Leak":re.compile(r"(wp-content|wp-includes|wp-admin)",re.IGNORECASE|re.DOTALL),
    "Java Error":re.compile(r"(java\.lang\.|exception\s+in\s+thread\s+\"main\")",re.IGNORECASE|re.DOTALL),
    "Open Redirect":re.compile(r"(=\s*https?:\/\/)",re.IGNORECASE|re.DOTALL),
    "Deserialization":re.compile(r"(java\.io\.objectinputstream|ysoserial|__proto__|constructor\.prototype)",re.IGNORECASE|re.DOTALL),
    "XXE":re.compile(r"(<!doctype\s+[^>]*\[.*<!entity\s+[^>]*system)",re.IGNORECASE|re.DOTALL),
    "File Upload":re.compile(r"(multipart/form-data.*filename=)",re.IGNORECASE|re.DOTALL),
    "Prototype Pollution":re.compile(r"(\.__proto__|object\.prototype|object\.setprototypeof)",re.IGNORECASE|re.DOTALL),
    "NoSQL Injection":re.compile(r"(db\.\w+\.find\(|\$\w+\{|{\s*\$where\s*:)",re.IGNORECASE|re.DOTALL),
    "Exposed Git Directory":re.compile(r"(\.git/HEAD|\.gitignore|\.git/config)",re.IGNORECASE|re.DOTALL),
    "Potential Secrets":re.compile(r"(aws_access_key_id|aws_secret_access_key|api_key|private_key|authorization:\s*bearer\s+[0-9a-z\-_\.]+)",re.IGNORECASE|re.DOTALL),
    "JWT Token Leak":re.compile(r"(eyjh[a-z0-9_-]*\.[a-z0-9_-]+\.[a-z0-9_-]+)",re.IGNORECASE|re.DOTALL),
    "ETC Shadow Leak":re.compile(r"/etc/shadow",re.IGNORECASE|re.DOTALL),
    "Possible Password Leak":re.compile(r"(password\s*=\s*\w+)",re.IGNORECASE|re.DOTALL),
    "CC Leak":re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "CRLF Injection":re.compile(r"(\r\n|%0d%0a|%0A%0D)",re.IGNORECASE|re.DOTALL),
    "HTTP Request Smuggling":re.compile(r"(content-length:\s*\d+.*\r?\n\s*transfer-encoding:\s*chunked|transfer-encoding:\s*chunked.*\r?\n\s*content-length:\s*\d+)",re.IGNORECASE|re.DOTALL),
    "LDAP Injection":re.compile(r"(\(\w+=\*\)|\|\(\w+=\*\)|\(\w+~=\*)",re.IGNORECASE|re.DOTALL),
    "XPath Injection":re.compile(r"(/[^/]+/|\[[^\]]+\]|text\(\)=)",re.IGNORECASE|re.DOTALL),
    "Exposed S3 Bucket":re.compile(r"s3\.amazonaws\.com",re.IGNORECASE),
    "Exposed Azure Blob":re.compile(r"blob\.core\.windows\.net",re.IGNORECASE),
    "Exposed K8s Secrets":re.compile(r"kube[\s_-]*config|k8s[\s_-]*secret|kubeadm[\s_-]*token",re.IGNORECASE|re.DOTALL),
    "npm Token":re.compile(r"npm[_-]token_[a-z0-9]{36}",re.IGNORECASE|re.DOTALL)
}

HEADER_PATTERNS = {
    "Missing Security Headers":["Content-Security-Policy","X-Content-Type-Options","X-Frame-Options","X-XSS-Protection","Strict-Transport-Security"],
    "Outdated or Insecure Server":re.compile(r"(apache/2\.2\.\d|nginx/1\.10\.\d|iis/6\.0|php/5\.2)",re.IGNORECASE),
}

VULN_EXPLANATIONS = {
    "SQL Error":"Server returned DB error messages.",
    "SQL Injection":"Likely injection in SQL queries.",
    "XSS":"Injected client-side scripts.",
    "Directory Listing":"Exposed directory contents.",
    "File Inclusion":"Local/remote file inclusion.",
    "Server Error":"HTTP 500 or similar response.",
    "Shellshock":"Bash vulnerability discovered.",
    "Remote Code Execution":"User input can run code.",
    "LFI/RFI":"File references for inclusion.",
    "SSRF":"Server-Side Request Forgery found.",
    "Path Traversal":"Possible directory traversal.",
    "Command Injection":"Shell commands inserted.",
    "WordPress Leak":"WordPress paths or files.",
    "Java Error":"Java exceptions or traces.",
    "Open Redirect":"Redirects to external URL.",
    "Deserialization":"Unsafe object deserialization.",
    "XXE":"XML External Entity usage.",
    "File Upload":"Multipart form can upload.",
    "Prototype Pollution":"JS prototype manipulation.",
    "NoSQL Injection":"Mongo-like injection references.",
    "Exposed Git Directory":"Git config or HEAD visible.",
    "Potential Secrets":"API keys or tokens leaked.",
    "JWT Token Leak":"JWT tokens exposed.",
    "ETC Shadow Leak":"Reference to /etc/shadow.",
    "Missing Security Headers":"Key headers absent.",
    "Outdated or Insecure Server":"Old or insecure server.",
    "Cookies lack 'Secure'/'HttpOnly'":"Cookie flags missing.",
    "Suspicious param name:":"Param name looks malicious.",
    "Suspicious param value in":"Param value looks malicious.",
    "Form uses GET with password/hidden":"Sensitive data in GET.",
    "Suspicious form fields (cmd/shell/token)":"Malicious field names.",
    "POST form without CSRF token":"Form missing CSRF token.",
    "Service Disruption":"5xx errors or repeated failures.",
    "Possible Password Leak":"Possible credential leakage.",
    "CC Leak":"Credit card pattern found.",
    "CRLF Injection":"New line injection discovered.",
    "HTTP Request Smuggling":"Conflicting request headers found.",
    "LDAP Injection":"Possible directory service injection.",
    "XPath Injection":"Injected XPath queries.",
    "Exposed S3 Bucket":"Cloud storage might be public.",
    "Exposed Azure Blob":"Unsecured Azure blob container.",
    "Exposed K8s Secrets":"Kubernetes secrets possibly exposed.",
    "npm Token":"npm private token possibly leaked.",
    "No explanation":"No explanation"
}

def label_entry(label,tactic,snippet,confidence=1.0):
    e = VULN_EXPLANATIONS.get(label,"No explanation")
    return (label,tactic,snippet,e,confidence)

print("[INFO] Preparing multi-vulnerability training samples...")
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
    "npm Token":(["npm_token_123456789012345678901234567890123456"],["safe usage"])
}

def tokenize(text):
    return re.findall(r"\w+", text.lower())

def build_vocab(samples, vocab_size=500):
    freq = {}
    for s in samples:
        for w in tokenize(s):
            freq[w] = freq.get(w, 0) + 1
    sorted_words = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    vocab = ["<unk>"] + [w for w,_ in sorted_words[:(vocab_size-1)]]
    word2idx = {w:i for i,w in enumerate(vocab)}
    return vocab, word2idx

def vectorize(text, word2idx):
    indices = []
    for w in tokenize(text):
        indices.append(word2idx.get(w, 0))
    return indices

@register_keras_serializable(package="Custom", name="EnhancedTFNet")
class EnhancedTFNet(tf.keras.Model):
    def __init__(self, vocab_size=500, embed_dim=256, hidden_dim=256, **kwargs):
        super().__init__(**kwargs)
        self.vocab_size = vocab_size
        self.embed_dim = embed_dim
        self.hidden_dim = hidden_dim
        self.embed = tf.keras.layers.Embedding(vocab_size, embed_dim)
        self.fc1 = tf.keras.layers.Dense(hidden_dim)
        self.fc2 = tf.keras.layers.Dense(hidden_dim)
        self.dropout = tf.keras.layers.Dropout(0.4)
        self.fc3 = tf.keras.layers.Dense(1)
    def call(self, x):
        x_embed = self.embed(x)
        x_mean = tf.reduce_mean(x_embed, axis=1)
        h1 = tf.nn.relu(self.fc1(x_mean))
        d = self.dropout(h1)
        h2 = tf.nn.relu(self.fc2(d))
        out = self.fc3(h2)
        return out
    def get_config(self):
        config = super().get_config()
        config.update({
            "vocab_size": self.vocab_size,
            "embed_dim": self.embed_dim,
            "hidden_dim": self.hidden_dim
        })
        return config
    @classmethod
    def from_config(cls, config):
        return cls(**config)

class TFClassifier:
    def __init__(self, vocab, word2idx, model_path, vocab_size=500, embed_dim=256, hidden_dim=256):
        self.vocab = vocab
        self.word2idx = word2idx
        self.vocab_size = vocab_size
        self.model_path = model_path
        self.model = EnhancedTFNet(vocab_size, embed_dim, hidden_dim)
        self.model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss=tf.keras.losses.BinaryCrossentropy(from_logits=True)
        )
    def fit(self, X_data, y_data, epochs=20, lr=0.001, batch_size=4):
        self.model.optimizer.lr = lr
        data_pairs = list(zip(X_data, y_data))
        for _ in range(epochs):
            random.shuffle(data_pairs)
            for i in range(0, len(data_pairs), batch_size):
                batch = data_pairs[i:i+batch_size]
                bx = [vectorize(x, self.word2idx) for x,_ in batch]
                by = [float(y) for _,y in batch]
                lens = [len(xx) for xx in bx]
                max_len = max(lens) if lens else 1
                padded = []
                for xx in bx:
                    padded.append(xx + [0]*(max_len - len(xx)))
                padded = tf.convert_to_tensor(padded, dtype=tf.int32)
                by = tf.convert_to_tensor(by, dtype=tf.float32)
                with tf.GradientTape() as tape:
                    logits = self.model(padded, training=True)
                    loss_value = tf.nn.sigmoid_cross_entropy_with_logits(
                        labels=by,
                        logits=tf.squeeze(logits, axis=-1)
                    )
                    loss_value = tf.reduce_mean(loss_value)
                grads = tape.gradient(loss_value, self.model.trainable_variables)
                self.model.optimizer.apply_gradients(zip(grads, self.model.trainable_variables))
        save_data = {"vocab": self.vocab,"word2idx": self.word2idx}
        base = os.path.splitext(self.model_path)[0]
        with open(base + "_vocab.json","w",encoding="utf-8") as f:
            json.dump(save_data, f)
        self.model.save(self.model_path)
    def predict_proba(self, text):
        data_idx = vectorize(text, self.word2idx)
        if len(data_idx)==0:
            data_idx = [0]
        padded = tf.convert_to_tensor([data_idx], dtype=tf.int32)
        logits = self.model(padded, training=False)
        prob = tf.sigmoid(logits)[0][0].numpy()
        return prob

def load_tf_model(path):
    base = os.path.splitext(path)[0]
    vocab_file = base + "_vocab.json"
    if not os.path.isfile(path) or not os.path.isfile(vocab_file):
        return None
    with open(vocab_file,"r",encoding="utf-8") as f:
        ckpt = json.load(f)
    vocab = ckpt["vocab"]
    word2idx = ckpt["word2idx"]
    model = tf.keras.models.load_model(path)
    classifier = TFClassifier(vocab, word2idx, path, len(vocab))
    classifier.model = model
    return classifier

def ml_detection_confidence(snippet, model):
    if not model:
        return (0.0, False)
    prob = model.predict_proba(snippet)
    return (prob, prob >= 0.5)

def train_base_ml_models():
    print("[INFO] Checking or training base ML models (XSS / SQL Injection)...")
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
        vocab, word2idx = build_vocab(X_data)
        clf = TFClassifier(vocab, word2idx, XSS_MODEL_PATH, len(vocab))
        clf.fit(X_data, y_data)

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
        vocab, word2idx = build_vocab(X_data)
        clf = TFClassifier(vocab, word2idx, SQLI_MODEL_PATH, len(vocab))
        clf.fit(X_data, y_data)

def train_all_vulnerability_models():
    print("[INFO] Checking or training multi vulnerability models...")
    if not os.path.isdir(MULTI_MODELS_DIR):
        os.makedirs(MULTI_MODELS_DIR)
    for vuln_name,(suspicious,benign) in MULTI_VULN_SAMPLES.items():
        mp = os.path.join(MULTI_MODELS_DIR,f"{vuln_name.replace(' ','_').replace(':','').replace('/','_')}.keras")
        if not os.path.isfile(mp):
            X_data = suspicious + benign
            y_data = [1]*len(suspicious) + [0]*len(benign)
            vocab, word2idx = build_vocab(X_data)
            clf = TFClassifier(vocab, word2idx, mp, len(vocab))
            clf.fit(X_data, y_data)

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

def fuzz_injection_tests(url):
    fs = []
    pl = [
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "; ls;",
        "&& cat /etc/passwd",
        "<img src=x onerror=alert(2)>",
        "'; DROP TABLE users; --",
        "|| ping -c 4 127.0.0.1 ||"
    ]
    def do_request(payload):
        try:
            tu = f"{url}?inj={urllib.parse.quote(payload)}"
            r = requests.get(tu,timeout=3,headers=CUSTOM_HEADERS)
            return scan_for_vuln_patterns(r.text)
        except:
            return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(pl)) as executor:
        future_to_payload = {executor.submit(do_request, p): p for p in pl}
        for fut in concurrent.futures.as_completed(future_to_payload):
            try:
                fs.extend(fut.result())
            except:
                pass
    return fs

def repeated_disruption_test(url,attempts=3):
    f = []
    def do_test(_):
        try:
            r = requests.get(url,timeout=3,headers=CUSTOM_HEADERS)
            if r.status_code>=500:
                return [label_entry("Service Disruption","frequent-request detection",str(r.status_code))]
        except:
            return [label_entry("Service Disruption","frequent-request detection","Exception")]
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=attempts) as executor:
        futures = [executor.submit(do_test, i) for i in range(attempts)]
        for fut in concurrent.futures.as_completed(futures):
            f.extend(fut.result())
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

global_xss_model = None
global_sqli_model = None
global_multi_models = {}

def scan_target(url):
    print(f"[INFO] Scanning target: {url}")
    print(f"[DETAIL] Detailed scanning of: {url}")
    ds = analyze_query_params(url)
    ds.extend(fuzz_injection_tests(url))
    ds.extend(repeated_disruption_test(url))
    try:
        r = requests.get(url,timeout=5,headers=CUSTOM_HEADERS)
        b = r.text[:MAX_BODY_SNIPPET_LEN]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as exe:
            future_p_tags = exe.submit(scan_for_vuln_patterns, b)
            future_h_tags = exe.submit(scan_response_headers, r.headers if ENABLE_HEADER_SCANNING else None)
            future_f_tags = exe.submit(parse_suspicious_forms, b) if ENABLE_FORM_PARSING else None
            future_d_tags = exe.submit(dom_based_xss_detection, b)
            p_tags = future_p_tags.result()
            h_tags = future_h_tags.result() if future_h_tags else []
            f_tags = future_f_tags.result() if future_f_tags else []
            d_tags = future_d_tags.result() if future_d_tags else []
        ml_tags = []
        sc_pattern = re.compile(r"<script\b.*?>(.*?)</script>",re.IGNORECASE|re.DOTALL)
        def check_each_model(snippet):
            m_results = []
            if global_xss_model:
                prob,pred = ml_detection_confidence(snippet,global_xss_model)
                if pred:
                    sn = snippet.strip()
                    if len(sn)>200: sn = sn[:200]+"..."
                    m_results.append(label_entry("XSS",f"ML-based detection (score={prob:.3f})",sn,prob))
            if global_sqli_model:
                prob,pred = ml_detection_confidence(snippet,global_sqli_model)
                if pred:
                    sn = snippet[:200]+"..." if len(sn)>200 else snippet
                    m_results.append(label_entry("SQL Injection",f"ML-based detection (score={prob:.3f})",sn,prob))
            for vn,mm in global_multi_models.items():
                prob,pred = ml_detection_confidence(snippet,mm)
                if pred:
                    sn = snippet[:200]+"..." if len(sn)>200 else snippet
                    m_results.append(label_entry(vn,f"ML-based detection (score={prob:.3f})",sn,prob))
            return m_results
        all_snippets = [b]
        all_snippets.extend(sc_pattern.findall(b))
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(all_snippets)) as exe:
            futs = [exe.submit(check_each_model, s_) for s_ in all_snippets]
            for f_ in concurrent.futures.as_completed(futs):
                ml_tags.extend(f_.result())
        all_tags = ds + p_tags + h_tags + f_tags + d_tags + ml_tags
        funcs = extract_js_functions(r.text)
        return {
            "url":url,
            "status_code":r.status_code,
            "reason":r.reason,
            "server":r.headers.get("Server","Unknown"),
            "matched_details":all_tags,
            "extracted_js_functions":funcs,
            "body":r.text
        }
    except Exception as e:
        return {
            "url":url,
            "error":str(e),
            "matched_details":ds,
            "server":"Unknown",
            "extracted_js_functions":[],
            "body":""
        }

def write_scan_results_text(rs,filename="scan_results.txt"):
    print("[INFO] Writing text results...")
    with open(filename,"w",encoding="utf-8") as f:
        for r in rs:
            f.write(f"Server causing detection: {r.get('server','Unknown')}\n")
            f.write(f"URL: {r['url']}\n")
            if "bfs_depth" in r:
                f.write(f"  PriorityBFS Depth: {r['bfs_depth']}\n")
            if "error" in r:
                f.write(f"  Error: {r['error']}\n")
                for pt,tac,snip,ex,conf in r["matched_details"]:
                    f.write(f"    {pt}\n      Tactic: {tac}\n      Explanation: {ex}\n      Snippet: {snip}\n")
            else:
                f.write(f"  Status: {r.get('status_code','N/A')} {r.get('reason','')}\n")
                if r["matched_details"]:
                    for pt,tac,snip,ex,conf in r["matched_details"]:
                        f.write(f"    {pt}\n      Tactic: {tac}\n      Explanation: {ex}\n      Snippet: {snip}\n")
            if r.get("extracted_js_functions"):
                f.write("  JS Functions:\n")
                for funcdef in r["extracted_js_functions"]:
                    f.write(f"    {funcdef}\n")
            f.write("\n")

def write_scan_results_json(rs):
    print("[INFO] Writing JSON results...")
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
            "extracted_js_functions":r.get("extracted_js_functions",[])
        }
        if "status_code" in r:
            i["status"] = f"{r.get('status_code','N/A')} {r.get('reason','')}"
        if "bfs_depth" in r:
            i["priority_bfs_depth"] = r["bfs_depth"]
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
        return {"url":url,"error":"Selenium not available","data":""}
    o = Options()
    o.add_argument("--headless=new")
    o.binary_location = "chrome/Google Chrome for Testing.app"
    s = ChromeService("chromedriver")
    try:
        try:
            d = webdriver.Chrome(service=s,options=o)
        except Exception as e:
            tb = traceback.format_exc()
            return {"url":url,"error":f"Chrome launch failed: {str(e)}\nTraceback: {tb}","data":""}
        try:
            d.get(url)
            c = d.page_source
        except Exception as e:
            tb = traceback.format_exc()
            d.quit()
            return {"url":url,"error":f"Chrome navigation failed: {str(e)}\nTraceback: {tb}","data":""}
        d.quit()
        return {"url":url,"error":"","data":c}
    except Exception as e:
        tb = traceback.format_exc()
        return {"url":url,"error":f"ChromeDriver error: {str(e)}\nTraceback: {tb}","data":""}

def plot_current_graph(graph, depth):
    G = nx.DiGraph()
    for node, neighbors in graph.items():
        for neigh in neighbors:
            G.add_edge(node, neigh)
    plt.figure(figsize=(10,6))
    pos = nx.spring_layout(G, k=0.3)
    nx.draw(G, pos, with_labels=True, node_size=400, font_size=8, arrows=True)
    plt.title(f"BFS Layer {depth}")
    plt.savefig(f"bfs_layer_{depth}.png")
    plt.close()

captured_flags = []

def detect_flags(content):
    hits = []
    patterns = [
        re.compile(r"ctf\{[^}]+\}", re.IGNORECASE),
        re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
        re.compile(r"capturetheflag", re.IGNORECASE),
        re.compile(r"htb\{[^}]+\}", re.IGNORECASE),
        re.compile(r"picoctf\{[^}]+\}", re.IGNORECASE)
    ]
    for pat in patterns:
        for m in pat.finditer(content):
            hits.append(m.group())
    return hits

def priority_bfs_crawl_and_scan(starts, max_depth=10):
    print("[INFO] Starting Priority BFS crawl and scan...")
    visited = set()
    graph = {}
    results = []
    pq = []
    for s in starts:
        heapq.heappush(pq, (0, s))
    http_executor = concurrent.futures.ThreadPoolExecutor(max_workers=50)
    bot_executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
    while pq:
        depth, url = heapq.heappop(pq)
        if depth > max_depth:
            break
        if url in visited:
            continue
        visited.add(url)
        print(f"[PRIORITY BFS] Processing: {url} at depth {depth}")
        f1 = http_executor.submit(scan_target, url)
        f2 = bot_executor.submit(scan_with_chromedriver, url)
        r1 = f1.result()
        r2 = f2.result()
        body1 = r1["body"] if "body" in r1 else ""
        body2 = r2["data"] if "data" in r2 else ""
        new_links_1 = extract_links_from_html(url, body1)
        new_links_2 = extract_links_from_html(url, body2)
        if url not in graph:
            graph[url] = set()
        for nl in new_links_1:
            if nl not in visited:
                graph[url].add(nl)
                heapq.heappush(pq, (depth+1, nl))
        for nl in new_links_2:
            if nl not in visited:
                graph[url].add(nl)
                heapq.heappush(pq, (depth+1, nl))
        combined_details = r1["matched_details"] if "matched_details" in r1 else []
        if r2["error"]:
            combined_details.append(label_entry("ChromeDriver Error","browser-based detection",r2["error"]))
        else:
            combined_details.extend(scan_for_vuln_patterns(body2))
        combined_js = r1.get("extracted_js_functions",[])
        if body2:
            combined_js.extend(extract_js_functions(body2))
        final = {
            "url":url,
            "server":r1.get("server","Unknown"),
            "status_code":r1.get("status_code","N/A"),
            "reason":r1.get("reason","N/A"),
            "error":r1.get("error","") or r2.get("error",""),
            "matched_details":combined_details,
            "extracted_js_functions":combined_js,
            "bfs_depth":depth
        }
        flag_matches_1 = detect_flags(body1)
        for fm in flag_matches_1:
            print(f"[FLAG] Found potential flag: {fm} in {url}")
            captured_flags.append({"flag":fm,"url":url})
        flag_matches_2 = detect_flags(body2)
        for fm in flag_matches_2:
            print(f"[FLAG] Found potential flag: {fm} in {url}")
            captured_flags.append({"flag":fm,"url":url})
        results.append(final)
        print(f"[PRIORITY BFS] Finished: {url} at depth {depth}")
        plot_current_graph(graph, depth)
    http_executor.shutdown()
    bot_executor.shutdown()
    return results

class VulnerabilityScannerEnv(gym.Env):
    def __init__(self, target_urls):
        super().__init__()
        self.target_urls = target_urls
        self.action_space = gym.spaces.Discrete(len(target_urls))
        self.observation_space = gym.spaces.Discrete(1)
        self.current_step = 0
        self.vulns_found = 0
    def reset(self):
        self.current_step = 0
        self.vulns_found = 0
        return 0
    def step(self, action):
        url = self.target_urls[action]
        r = scan_target(url)
        found = len(r["matched_details"])
        reward = found
        for det in r["matched_details"]:
            if "capturetheflag" in det[2].lower():
                reward += 100
        self.vulns_found += found
        self.current_step += 1
        done = (self.current_step >= 5)
        return 0, reward, done, {}
    def render(self, mode="human"):
        pass

def train_reinforcement_model(urls):
    print("[INFO] Training simple reinforcement model...")
    env = VulnerabilityScannerEnv(urls)
    q_table = [0.0 for _ in range(env.action_space.n)]
    alpha = 0.1
    gamma = 0.9
    epsilon = 0.2
    for episode in range(500):
        obs = env.reset()
        done = False
        while not done:
            if random.random() < epsilon:
                action = random.randrange(env.action_space.n)
            else:
                action = q_table.index(max(q_table))
            next_obs, reward, done, _ = env.step(action)
            q_table[action] += alpha * (reward + gamma * max(q_table) - q_table[action])

def main():
    sys.stdout.reconfigure(line_buffering=True)
    print("[INFO] Starting main function...")
    train_base_ml_models()
    print("[INFO] Base ML models ready.")
    train_all_vulnerability_models()
    print("[INFO] All vulnerability models ready.")
    global global_xss_model, global_sqli_model, global_multi_models
    global_xss_model = load_tf_model(XSS_MODEL_PATH)
    global_sqli_model = load_tf_model(SQLI_MODEL_PATH)
    for vn in MULTI_VULN_SAMPLES.keys():
        mp = os.path.join(MULTI_MODELS_DIR,f"{vn.replace(' ','_').replace(':','').replace('/','_')}.keras")
        global_multi_models[vn] = load_tf_model(mp)
    train_reinforcement_model(test_sites)
    print("[INFO] Reinforcement model trained.")
    all_results = priority_bfs_crawl_and_scan(test_sites,10)
    print("[INFO] Priority BFS crawl and scan completed.")
    for r in all_results:
        print(f"\nServer: {r.get('server','Unknown')} | {r['url']} | PriorityBFS Depth: {r.get('bfs_depth','N/A')}")
        if "error" in r and r["error"]:
            print(f"  Error: {r['error']}")
        for pt,tactic,snippet,explanation,conf in r["matched_details"]:
            print(f"  Detected: {pt}\n    Explanation: {explanation}\n    Tactic: {tactic}\n    Snippet: {snippet}")
        if r.get("extracted_js_functions"):
            print("  Extracted JS Functions:")
            for f_ in r["extracted_js_functions"]:
                print(f"    {f_}")
    write_scan_results_text(all_results,"scan_results.txt")
    write_scan_results_json(all_results)
    if captured_flags:
        print("[INFO] Writing successful_captures.json for discovered flags...")
        with open("successful_captures.json","w",encoding="utf-8") as f:
            json.dump(captured_flags,f,indent=2)
    print("[INFO] Scan results have been written to disk.")

if __name__=="__main__":
    main()