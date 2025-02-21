import os
import json
import time

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
    op = os.path.join(d, "scan_results.json")
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
    with open(op, "w", encoding="utf-8") as f:
        json.dump(o, f, indent=2)
