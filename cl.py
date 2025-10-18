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
import sys

# ---------------- مسیر فایل‌ها ----------------
TEXT_NORMAL = "test.txt"
TEXT_FINAL = "almasi.txt"

# ---------------- لینک‌ها (دقت: دومین بخش ریپو تغییر یافته به almasi62) ----------------
LINKS_PATH = [
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vmess.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/vless.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/trojan.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/ss.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/h2.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/shah.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/shah10.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/shah20.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/shah30.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/shah40.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/shah50.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/shah60.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/shah70.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/shah80.txt",
    "https://raw.githubusercontent.com/tepo80/almasi62/main/shah90.txt"
]

MAX_THREADS = 20
MAX_PING_MS = 1200  # میلی‌ثانیه، اگر پینگ بیشتر از این شد حذف می‌شود

# ---------------- دریافت خطوط از لینک ----------------
def fetch_lines(url):
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            content = resp.read()
            # سعی می‌کنیم utf-8 سپس fallback به latin-1
            try:
                text = content.decode("utf-8", errors="ignore")
            except:
                text = content.decode("latin-1", errors="ignore")
            lines = text.splitlines()
            return [line.strip() for line in lines if line.strip()]
    except Exception as e:
        print(f"[ERROR] Cannot fetch {url}: {e}")
        return []

# ---------------- حذف خطوط تکراری ----------------
def unique_lines(lines):
    seen = set()
    result = []
    for line in lines:
        if line not in seen:
            result.append(line)
            seen.add(line)
    return result

# ---------------- پینگ ----------------
def ping(host, count=1, timeout=1):
    """
    مقدار بازگشتی: زمان (ms) یا inf اگر پینگ قابل محاسبه نبود
    توجه: پارامترهای دستور ping بر اساس سیستم عامل تنظیم می‌شود.
    """
    param_count = "-n" if platform.system().lower() == "windows" else "-c"
    # برای ویندوز از -w (timeout میلی‌ثانیه برای هر پینگ)، برای یونیکس از -W (ثانیه) استفاده می‌شود.
    if platform.system().lower() == "windows":
        param_timeout = "-w"
        timeout_val = str(timeout * 1000)  # تبدیل به میلی‌ثانیه
    else:
        param_timeout = "-W"
        timeout_val = str(timeout)  # ثانیه

    try:
        cmd = ["ping", param_count, str(count), param_timeout, timeout_val, host]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout + 3)
        output = result.stdout + "\n" + result.stderr

        # تلاش برای یافتن زمان در خروجی‌های متنوع:
        # مثال ویندوز: "time=12ms" یا "time<1ms"
        m = re.search(r'time[=<]\s*(\d+\.?\d*)\s*ms', output, re.IGNORECASE)
        if not m:
            # برخی سیستم‌ها خروجی به صورت "time=12.3 ms" یا "time=12.3ms"
            m = re.search(r'time[=<]\s*(\d+\.?\d*)', output, re.IGNORECASE)
        if m:
            return float(m.group(1))
        # گاهی در mac/linux خروجی: "min/avg/max/mdev = 0.042/0.042/0.042/0.000 ms"
        m2 = re.search(r'=?\s*([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)\s*ms', output)
        if m2:
            # avg در گروه دوم
            return float(m2.group(2))
    except Exception:
        pass
    return float('inf')

# ---------------- استخراج هاست و پورت از کانفیگ ----------------
def extract_address(config_line):
    """
    تلاش برای استخراج hostname/IP و پورت:
    - vmess://<base64-json>
    - vless://<...>@host:port...
    - trojan://<...>@host:port...
    - hysteria2/hy2://host:port
    در صورت عدم توانایی در استخراج، (None, None) باز می‌گردد.
    """
    try:
        line = config_line.strip()
        if line.startswith("vmess://"):
            encoded = line.split("://", 1)[1].split("#")[0]
            # بعضی بیس64ها padding ندارند، اضافه می‌کنیم
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += "=" * (4 - missing_padding)
            try:
                decoded = base64.b64decode(encoded).decode('utf-8', errors="ignore")
                data = json.loads(decoded)
                host = data.get("add") or data.get("address")
                port = int(data.get("port", 443))
                return host, port
            except Exception:
                return None, None

        # vless/trojan with userinfo before @
        m = re.match(r'^[^:]+://[^@]+@\[?([^\]]+)\]?:?(\d+)?', line)
        if m:
            host = m.group(1)
            port = m.group(2)
            port = int(port) if port else None
            return host, port or 443

        # hysteria2/hy2 style: hysteria2://host:port or hy2://host:port
        if line.startswith("hy2://") or line.startswith("hysteria2://"):
            m2 = re.match(r'^[^:]+://\[?([^\]]+)\]?:?(\d+)', line)
            if m2:
                return m2.group(1), int(m2.group(2))

    except Exception:
        pass
    return None, None

# ---------------- پردازش پینگ ----------------
def process_ping(configs):
    """
    پارامتر: لیست خطوط کانفیگ
    خروجی: لیست خطوطی که پینگ معتبر داشته‌اند (مرتب شده بر اساس زمان پینگ)
    """
    results = []
    lock = threading.Lock()
    threads = []

    def worker(cfg_line):
        host, port = extract_address(cfg_line)
        if host:
            # اگر hostname با پروتکل یا پراکسی شروع می‌شد آن را پاک می‌کنیم
            # همچنین اگر host شامل path بود، فقط بخش host را نگه می‌داریم
            host_clean = host.split("/")[0]
            # حذف اسکیپ‌های احتمالی
            host_clean = host_clean.strip()
            ping_time = ping(host_clean)
            if ping_time < MAX_PING_MS:
                with lock:
                    results.append((cfg_line, ping_time))

    for line in configs:
        t = threading.Thread(target=worker, args=(line,))
        threads.append(t)
        t.start()
        # مدیریت محدودیت تعداد تردها
        if len(threads) >= MAX_THREADS:
            for th in threads:
                th.join()
            threads = []

    # منتظر ماندن برای تردهای باقی‌مانده
    for t in threads:
        t.join()

    # مرتب‌سازی بر پایه پینگ (کوچک به بزرگ)
    results.sort(key=lambda x: x[1])
    return [cfg for cfg, _ in results]

# ---------------- ذخیره فایل‌ها ----------------
def save_files(normal_lines, final_lines):
    try:
        with open(TEXT_NORMAL, "w", encoding="utf-8") as f:
            f.write("\n".join(normal_lines))
        with open(TEXT_FINAL, "w", encoding="utf-8") as f:
            f.write("\n".join(final_lines))
    except Exception as e:
        print(f"[ERROR] Cannot write files: {e}")

# ---------------- اجرای اصلی ----------------
def update_all():
    print("[*] Fetching sources...")
    all_lines = []
    for link in LINKS_PATH:
        print(f"[*] Fetching: {link}")
        lines = fetch_lines(link)
        print(f"    -> got {len(lines)} lines")
        all_lines.extend(lines)

    print(f"[*] Total lines fetched (raw): {len(all_lines)}")

    all_lines = unique_lines(all_lines)
    print(f"[*] Unique lines after dedupe: {len(all_lines)}")

    if not all_lines:
        print("[WARN] No configs found. Exiting.")
        return

    print("[*] Stage 1: First ping check (basic filtering)...")
    normal_lines = process_ping(all_lines)
    print(f"[INFO] Stage 1 passed: {len(normal_lines)} configs")

    print("[*] Stage 2: Detailed ping stability check...")
    final_lines = process_ping(normal_lines)
    print(f"[INFO] Stage 2 passed: {len(final_lines)} configs")

    save_files(normal_lines, final_lines)
    print(f"[✅] Update complete. Saved {len(normal_lines)} -> {TEXT_NORMAL} and {len(final_lines)} -> {TEXT_FINAL}")

if __name__ == "__main__":
    try:
        print("[*] Starting advanced auto-updater for TXT sources (cl)...")
        update_all()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        sys.exit(1)
