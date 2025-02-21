import os
import time
import argparse
from test_sites import test_sites
from crawler import bfs_crawl_and_scan
from output import write_scan_results_text, write_scan_results_json

def main():
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
        import json
        json.dump(bfs_tree, f, indent=2)

    print("\nPriorityBFS Tree:")
    for node, children in bfs_tree.items():
        print(node, "->", children)

    write_scan_results_text(results, "scan_results.txt")
    write_scan_results_json(results)

if __name__ == "__main__":
    main()
