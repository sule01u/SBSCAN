#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     utils.py
   Description :  代理
   Author :       sule01u
   date：          2023/10/4
"""

import requests
from configs.custom_headers import DEFAULT_HEADER, TIMEOUT
from utils.format_utils import format_url


def get_with_proxy(url, proxy):
    proxies = {
        "http": format_url(proxy, "http"),
        "https": format_url(proxy, "https")
    }
    print(proxies)
    return requests.get(url, proxies=proxies, headers=DEFAULT_HEADER, verify=False, timeout=TIMEOUT, stream=True)
