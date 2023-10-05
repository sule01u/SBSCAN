#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     format_utils.py
   Description :  格式化
   Author :       sule01u
   date：          2023/10/5
"""


def format_url(url):
    """构造完整的URL"""
    if '://' not in url:
        url = f"http://{url}"
    return f"{url.rstrip('/')}/"