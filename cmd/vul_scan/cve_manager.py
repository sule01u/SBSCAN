#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_manager.py
   Description :
   Author :       sule01u
   date：          2023/10/5
"""
from concurrent.futures import ThreadPoolExecutor
from . import cve_2022_22963, cve_2022_22947
from termcolor import cprint
from utils.reporter import save_cve_report

# CVE模块列表
CVE_MODULES = [
    cve_2022_22963,
    cve_2022_22947
]


def run_single_url_cve_checks(url, proxies=None):
    results = []
    for module in CVE_MODULES:
        status, result = module.check(url, proxies)
        if status:
            cprint(f"[+] 检测到漏洞: {result}", "red")
            save_cve_report(result['CVE_ID'], result['URL'], result['Details'])  # 保存每个CVE的报告
            results.append(result)
    return results


def run_cve_checks(urls, proxy=None, threads=10):
    cprint(f"[+]开始CVE扫描，一共 {len(urls)} 个URLs，使用 {threads} 个线程", "yellow")
    all_results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(run_single_url_cve_checks, url, proxy): url for url in urls}
        for future in futures:
            url = futures[future]
            try:
                results = future.result()
                all_results.extend(results)
            except Exception as e:
                cprint(f"[-] 检测 {url} 异常，原因: {e}", "red")
    if not all_results:
        cprint("[-]未检测到spring相关漏洞", "yellow")
    cprint("[+]CVE扫描完成================================\n", "yellow")
    return all_results
