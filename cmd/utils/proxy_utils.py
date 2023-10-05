#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     utils.py
   Description :  代理
   Author :       sule01u
   date：          2023/10/4
"""

import requests
from cmd.custom_headers import DEFAULT_HEADER, TIMEOUT


def get_with_proxy(url, proxy):
    proxies = {
        'http': proxy,
        'https': proxy
    }
    return requests.get(url, proxies=proxies, headers=DEFAULT_HEADER, verify=False, timeout=TIMEOUT)
