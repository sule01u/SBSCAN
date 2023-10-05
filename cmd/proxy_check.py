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
from configs import custom_headers
from utils.proxy_utils import get_with_proxy
import requests
requests.packages.urllib3.disable_warnings()


TEST_URL = "https://www.baidu.com/"


def is_proxy_working(proxy):
    cprint(f"================检测代理可用性中================", "yellow")
    try:
        res = get_with_proxy(TEST_URL, proxy)
        if res.status_code == 200:
            cprint(f"[+] 代理可用", "yellow")
    except KeyboardInterrupt:
        sys.exit()
    except:
        cprint(f"[-] 代理不可用，请更换代理！", "magenta")
        sys.exit()
