#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     network_utils.py
   Description :  获取指定目标的响应
   Author :       sule01u
   date：          2023/10/5
"""
import sys
import requests
from termcolor import cprint
from cmd.custom_headers import DEFAULT_HEADER
from cmd.utils.proxy_utils import get_with_proxy


def fetch_target_content(target, proxies):
    """获取目标URL的响应"""
    headers = DEFAULT_HEADER
    try:
        if proxies:
            response = get_with_proxy(target, proxies)
        else:
            response = requests.get(target, headers=headers, timeout=16, verify=False)

        return response
    except requests.ConnectionError:
        cprint(f"\n[-] URL {target} 连接错误", "magenta")
    except requests.Timeout:
        cprint(f"\n[-] URL {target} 请求超时", "magenta")
    except KeyboardInterrupt:
        cprint("\n[-] 您已手动退出程序", 'red')
        sys.exit()
    except Exception as e:
        cprint(f"\n[-] URL {target} 请求时出现错误，原因: {e}", "magenta")
    return None