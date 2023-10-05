#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     proxy_check.py
   Description :
   Author :       suleo
   date：          2023/10/4
"""
import sys
from termcolor import cprint
from cmd import custom_headers
import requests
requests.packages.urllib3.disable_warnings()


TEST_URL = "https://www.baidu.com/"


def is_proxy_working(proxy):
    proxies = {
        "http": "http://%(proxy)s/" % {'proxy': proxy},
        "https": "http://%(proxy)s/" % {'proxy': proxy}
    }
    cprint(f"================检测代理可用性中================", "yellow")
    headers = custom_headers.DEFAULT_HEADER
    try:
        res = requests.get(TEST_URL, timeout=10, proxies=proxies, verify=False, headers=headers)
        if res.status_code == 200:
            cprint(f"[+] 代理可用", "yellow")
    except KeyboardInterrupt:
        sys.exit()
    except:
        cprint(f"[-] 代理不可用，请更换代理！", "magenta")
        sys.exit()
