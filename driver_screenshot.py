import os
import time
import random
import subprocess
import sys

def scan_with_chromedriver(url, screenshot_dir):
    try:
        screenshot_file = os.path.join(screenshot_dir, f"screenshot_{int(time.time()*1000)}.png")
        cmd = [
            "chromedriver",
            "--url-base=/wd/hub"
        ]
        chrome_cmd = [
            "chrome-headless-shell",
            "--no-sandbox",
            "--headless",
            f"--screenshot={screenshot_file}",
            url
        ]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        time.sleep(random.uniform(1,2))
        p = subprocess.run(chrome_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        data = p.stdout.decode('utf-8', errors='ignore') + p.stderr.decode('utf-8', errors='ignore')
        return {"error":"","data":data,"screenshot":screenshot_file}
    except Exception as e:
        return {"error":str(e),"data":"","screenshot":""}
