#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import json
import base64
import urllib.request
import subprocess
import platform
import threading
import re

# ---------------- مسیر فایل‌ها ----------------
TEXT_NORMAL = "test.txt"
TEXT_FINAL = "almasi.txt"

LINKS_PATH = [
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vip.json",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vip10.json",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vip20.json",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vip30.json",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vip40.json",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vip50.json",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vip60.json",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vip70.json",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vip80.json",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vip90.json"
]

MAX_THREADS = 15
MAX_PING_MS = 1500

def fetch_lines(url):
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            lines = resp.read().decode(errors="ignore").splitlines()
            return [line.strip() for line in lines if line.strip()]
    except Exception as e:
        print(f"[ERROR] Cannot fetch {url}: {e}")
        return []

def unique_lines(lines):
    seen = set()
    result = []
    for line in lines:
        if line not in seen:
            result.append(line)
            seen.add(line)
    return result

def ping(host, count=1, timeout=1):
    param_count = "-n" if platform.system().lower() == "windows" else "-c"
    param_timeout = "-w" if platform.system().lower() == "windows" else "-W"
    try:
        cmd = ["ping", param_count, str(count), param_timeout, str(timeout), host]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        match = re.search(r'time[=<]\s*(\d+\.?\d*)', output)
        if match:
            return float(match.group(1))
    except:
        pass
    return float('inf')

def extract_address(config_line):
    try:
        if config_line.startswith("vmess://"):
            encoded = config_line.split("://", 1)[1].split("#")[0]
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += "=" * (4 - missing_padding)
            data = json.loads(base64.b64decode(encoded).decode('utf-8', errors="ignore"))
            host = data.get("add") or data.get("address")
            return host
        elif config_line.startswith(("vless://", "trojan://", "hy2://", "hysteria2://")):
            match = re.match(r'^[^:]+://[^@]+@([^:]+):(\d+)', config_line)
            if match:
                return match.group(1)
    except:
        pass
    return None

def process_ping(configs):
    results = []
    lock = threading.Lock()
    threads = []

    def worker(cfg_line):
        host = extract_address(cfg_line)
        if host:
            ping_time = ping(host)
            if ping_time < MAX_PING_MS:
                with lock:
                    results.append((cfg_line, ping_time))

    for line in configs:
        t = threading.Thread(target=worker, args=(line,))
        threads.append(t)
        t.start()
        if len(threads) >= MAX_THREADS:
            for th in threads:
                th.join()
            threads = []

    for t in threads: 
        t.join()
    results.sort(key=lambda x: x[1])
    return [cfg for cfg, _ in results]

def save_files(normal_lines, final_lines):
    with open(TEXT_NORMAL, "w", encoding="utf-8") as f:
        f.write("\n".join(normal_lines))
    with open(TEXT_FINAL, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines))

def update_all():
    print("[*] Fetching sources...")
    all_lines = []
    for link in LINKS_PATH:
        all_lines.extend(fetch_lines(link))
    print(f"[*] Total lines fetched: {len(all_lines)}")

    all_lines = unique_lines(all_lines)
    normal_lines = process_ping(all_lines)
    final_lines = process_ping(normal_lines)

    save_files(normal_lines, final_lines)
    print("[✅] Update complete. Files saved as test.txt and almasi.txt")

if __name__ == "__main__":
    print("[*] Starting cl2.py process...")
    update_all()
