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
from utils.custom_headers import USER_AGENTS
from utils.logging_config import configure_logger
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()


def check(target_url, proxies=None):
    """
    对给定的目标URL检测CVE-2022-22963漏洞。
    参数:
    - target_url: 待检测的目标URL
    - proxies: 代理配置
    """
    CVE_ID = "CVE-2022-22963"
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': random.choice(USER_AGENTS),
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # 构建请求URL
    request_url = target_url.rstrip("/") + "/functionRouter"

    try:
        response = requests.post(request_url, headers=headers, data='test', verify=False, timeout=6, proxies=proxies)

        # 检查响应内容来判断漏洞是否存在
        if response.status_code == 500 and '"error":"Internal Server Error"' in response.text:
            logger.info(f"URL: {request_url} 存在{CVE_ID}漏洞")
            return True, {
                "CVE_ID": CVE_ID,
                "URL": request_url,
                "Details": f"检测到{CVE_ID}的RCE漏洞"
            }
        logger.info(f"URL: {target_url} 未检测到{CVE_ID}的RCE漏洞")
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


if __name__ == "__main__":
    is_vul, res = check("http://localhost:8080/", proxies={})
    print(is_vul, res)
