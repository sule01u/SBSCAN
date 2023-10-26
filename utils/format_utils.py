#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     format_utils.py
   Description :
   Author :       sule01u
   date：          2023/10/5
"""
from urllib.parse import urlparse
from utils.logging_config import configure_logger
logger = configure_logger(__name__)


class FormatterUtils:
    def format_url(self, url: str) -> str:
        """
        格式化url
        """
        if "." not in url:
            return ""
        url = url if url.startswith(('http://', 'https://')) else 'http://' + url
        if not self.is_valid_url(url.strip()):
            logger.error(f"Error: '{url}' is not a valid URL format.")
            return ""

        return url.rstrip("/") + "/"

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """
        验证url格式有效性
        """
        try:
            result = urlparse(url)
            return result.scheme in ['http', 'https'] and "." in result.netloc and result.scheme and result.netloc
        except ValueError:
            return False

    def format_proxy(self, proxy: str) -> dict:
        """
        格式化proxy
        """
        try:
            formated_proxy = self.format_url(proxy)
            if not formated_proxy:
                return {}
            result = urlparse(formated_proxy)
            return {
                "http": f"http://{result.netloc}",
                "https": f"https://{result.netloc}"
            }
        except ValueError:
            raise ValueError


if __name__ == '__main__':
    f = FormatterUtils()
    print(f.format_url("https://www.baidu.com:8080"))
    print(f.format_url("http://www.baidu.com"))
    print(f.format_url("baidu.com"))
    print(f.format_url("1.2.3.4"))
    print(f.format_url("www"))
    print(f.format_proxy("{}"))
