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
logger = configure_logger(__name__)  # 使用自定义日志配


def format_url(url):
    """
    格式化url
    """
    if not url.startswith(('http://', 'https://')):
        url = ('http://' + url).rstrip("/") + "/"
    if not is_valid_url(url):
        logger.error(f"Error: '{url}' is not a valid URL format.")
        return None

    return url


def is_valid_url(url):
    """
    验证url格式有效性
    """
    try:
        result = urlparse(url)
        # 一个有效的URL应该有scheme(如http)和netloc(如www.baidu.com)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def format_proxy(proxy):
    """
    格式化proxy
    """
    formated_proxy = format_url(proxy)
    if not formated_proxy:
        return {}
    result = urlparse(formated_proxy)
    return {
        "http": f"http://{result.netloc}",
        "https": f"https://{result.netloc}"
    }
