#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     run.py
   Description :
   Author :       sule01u
   date：          2023/10/4
"""
from termcolor import cprint
import requests
from concurrent.futures import ThreadPoolExecutor
from configs.rule import LEAK_RULES
from utils.format_utils import format_url
from utils.req_utils import fetch_target_content
from utils.reporter import save_leak_report

requests.packages.urllib3.disable_warnings()


def single_scan(url, proxy):
    """扫描单个URL查找脆弱路径"""
    vulnerable_paths = []

    for path, keyword in LEAK_RULES.items():
        url = format_url(url, "http")
        target = url + path.strip()
        response = fetch_target_content(target, proxy)
        try:
            if "text/event-stream" in response.headers.get("Content-Type", ""):
                cprint(f"[+] 状态码{response.status_code} 信息泄露URL为:{target} 页面, SSE数据流", "red",
                       attrs=["bold", "reverse"])
                vulnerable_paths.append(target)
                continue
            if response and response.status_code == 200:
                cprint(f"[+] 状态码{response.status_code} 信息泄露URL为:{target} 页面长度为:{len(response.content)}", "red",
                       attrs=["bold", "reverse"])
                vulnerable_paths.append(target)
            else:
                pass
                # cprint(f"[-] 状态码{response.status_code} 无法访问 URL为:{target}", "yellow")
        except Exception as e:
            cprint(f"[-] {e} 无法访问 URL为:{target}", "yellow")

    return vulnerable_paths


def perform_scan(urls, proxy, threads):
    """并发扫描多个URL"""
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(single_scan, url, proxy): url for url in urls}

        for future in futures:
            url = futures[future]
            try:
                results = future.result()
                if results:
                    save_leak_report(url, results)  # 保存结果到指定的输出文件
                else:
                    cprint(f"[-] 未检测到有站点存在敏感路径开放", "red")
            except Exception as e:
                cprint(f"[-] 扫描 {url} 失败，原因: {e}", "red")


def scan(urls, proxy, threads=10):
    """主要的扫描函数，处理提供的URLs"""
    if not urls:
        cprint("[-]没有提供URL进行扫描", "red")
        return

    cprint(f"[+]正在检测 {len(urls)} 个URLs的所有敏感路径，使用 {threads} 个线程，请稍后", "yellow")
    perform_scan(urls, proxy, threads)
    cprint("[+]信息泄漏扫描完成================================\n", "yellow")
