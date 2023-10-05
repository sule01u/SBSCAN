#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     reporter.py
   Description :
   Author :       suleo
   date：          2023/10/4
"""
import datetime
import os
from termcolor import cprint


def gene_path(mode):
    # 获取当前日期
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')
    filename = f"{mode}-Reports-{current_date}.txt"

    # 确保输出目录存在
    if not os.path.exists('output'):
        os.makedirs('output')

    # 完整路径
    filepath = os.path.join('output', filename)
    return filepath


def save_leak_report(url, results):
    """
    保存给定URL的扫描结果到指定的输出文件中。
    """
    filepath = gene_path("leak")
    with open(filepath, 'a', encoding="utf-8") as f:
        f.write(f"\n\n{url}扫描结果:\n")
        for path in results:
            f.write(f"    {path}\n")


def save_cve_report(cve_id, url, details):
    """
    将CVE的详细报告保存到文件中。
    """

    filepath = gene_path("cve")
    with open(filepath, 'a') as f:
        # 使用冒号分隔CVE ID, URL, 和详情，并写入一行
        f.write(f"{cve_id}:{url}:{details}\n")