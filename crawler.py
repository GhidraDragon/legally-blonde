import heapq
import concurrent.futures
import time
import random
import json
from bs4 import BeautifulSoup
import urllib.parse
from scanner import scan_target, scan_for_vuln_patterns, extract_js_functions, label_entry
from driver_screenshot import scan_with_chromedriver

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
