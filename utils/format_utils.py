#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     format_utils.py
   Description :   URL和代理格式化工具类
   Author :       sule01u
   date：          2023/10/5
"""
import re
from urllib.parse import urlparse
from utils.logging_config import configure_logger

# 初始化日志记录
logger = configure_logger(__name__)

# URL 正则表达式用于进一步精确验证 URL 格式
URL_REGEX = re.compile(
    r'^(https?://)?'  # http:// or https://
    r'(([A-Za-z0-9$_.+!*\'(),;?&=-]|%[0-9A-Fa-f]{2})+(:([A-Za-z0-9$_.+!*\'(),;?&=-]|%[0-9A-Fa-f]{2})+)?@)?'  # username:password@
    r'([A-Za-z0-9.-]+|(\[([A-Fa-f0-9:.]+)\]))'  # domain or IP address
    r'(:\d+)?'  # :port
    r'(/([A-Za-z0-9$_.+!*\'(),;?&=-]|%[0-9A-Fa-f]{2})*)*'  # path
    r'(\?([A-Za-z0-9$_.+!*\'(),;?&=-]|%[0-9A-Fa-f]{2})*)?'  # query
    r'(#([A-Za-z0-9$_.+!*\'(),;?&=-]|%[0-9A-Fa-f]{2})*)?$',  # fragment
    re.IGNORECASE
)

# 代理正则表达式，用于验证代理格式的有效性
PROXY_REGEX = re.compile(
    r'^(http://|https://)?'  # 可选的 http:// 或 https:// 前缀
    r'(([A-Za-z0-9$_.+!*\'(),;?&=-]|%[0-9A-Fa-f]{2})+(:([A-Za-z0-9$_.+!*\'(),;?&=-]|%[0-9A-Fa-f]{2})+)?@)?'  # 可选的 username:password@
    r'([A-Za-z0-9.-]+|(\[([A-Fa-f0-9:.]+)\]))'  # 域名或 IP 地址
    r'(:\d+)?$',  # 可选的端口号
    re.IGNORECASE
)

class FormatterUtils:
    def format_url(self, url: str) -> str:
        """
        格式化 URL，并验证其有效性
        :param url: 需要格式化的 URL 字符串
        :return: 格式化后的 URL 或空字符串（如果格式无效）
        """
        # 如果 URL 中没有包含 "."，则直接返回空字符串，表示无效
        if "." not in url:
            logger.error(f"Invalid URL format: '{url}' - No domain found.")
            return ""

        # 如果 URL 没有 http 或 https 前缀，则默认加上 http
        if not url.lower().startswith(('http://', 'https://')):
            url = 'http://' + url

        # 去除 URL 结尾的 "/"
        url = url.rstrip("/")

        # 验证 URL 格式
        if not self.is_valid_url(url):
            logger.error(f"Invalid URL format: '{url}'.")
            return ""

        # 返回格式化后的 URL，并在结尾加上 "/"
        return url + "/"

    def is_valid_url(self, url: str) -> bool:
        """
        使用正则表达式验证 URL 的格式有效性
        :param url: 需要验证的 URL 字符串
        :return: 如果格式有效，返回 True；否则返回 False
        """
        # 使用正则表达式验证 URL
        if re.match(URL_REGEX, url):
            return True
        return False

    def format_proxy(self, proxy: str) -> dict:
        """
        格式化代理地址，并返回包含 http 和 https 的代理字典
        :param proxy: 需要格式化的代理地址（支持 http 或 https）
        :return: 格式化后的代理字典，或空字典（如果格式无效）
        """
        # 先检查代理格式是否符合基本格式
        if not self.is_valid_proxy(proxy):
            logger.error(f"Invalid proxy format: '{proxy}'.")
            return {}

        # 尝试解析代理地址，并生成包含 http 和 https 的代理字典
        try:
            result = urlparse(proxy if proxy.startswith(("http://", "https://")) else "http://" + proxy)
            return {
                "http": f"http://{result.netloc}",
                "https": f"https://{result.netloc}"
            }
        except ValueError as e:
            logger.error(f"Error formatting proxy: {proxy} - {e}")
            return {}

    def is_valid_proxy(self, proxy: str) -> bool:
        """
        验证代理格式是否有效
        :param proxy: 需要验证的代理地址
        :return: 如果代理格式有效，返回 True；否则返回 False
        """
        # 使用正则表达式验证代理格式
        if re.match(PROXY_REGEX, proxy):
            return True
        return False


if __name__ == '__main__':
    f = FormatterUtils()
    # 测试格式化 URL
    print(f.format_url("https://www.xxx.com:8080"))  # 输出: https://www.baidu.com:8080/
    print(f.format_url("http://www.xxx.com"))         # 输出: http://www.baidu.com/
    print(f.format_url("xxx.com"))                    # 输出: http://baidu.com/
    print(f.format_url("1.2.3.4"))                      # 输出: http://1.2.3.4/
    print(f.format_url("www"))                          # 输出: 空字符串（无效 URL）

    # 测试格式化代理地址
    print(f.format_proxy("http://user:pass@proxy.com:8080"))  # 输出: {'http': 'http://user:pass@proxy.com:8080', 'https': 'https://user:pass@proxy.com:8080'}
    print(f.format_proxy("proxy.com:8080"))                   # 输出: {'http': 'http://proxy.com:8080', 'https': 'https://proxy.com:8080'}
    print(f.format_proxy("{}"))                               # 输出: 空字典（无效代理）