#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     fingerprint_detector.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import hashlib
import requests
from utils.custom_headers import DEFAULT_HEADER
from utils.logging_config import configure_logger

logger = configure_logger(__name__)


class FingerprintDetector:
    SPRING_FAVICON_HASH = "0488faca4c19046b94d07c3ee83cf9d6"
    PATHS = ["/favicon.ico", "/"]

    def __init__(self, proxy_manager):
        self.proxy = proxy_manager.get_proxy()

    def is_spring_app(self, url):
        """
        检测目标站点是否使用Spring框架
        """
        for path in self.PATHS:
            full_url = url.rstrip("/") + path
            logger.debug(full_url)
            response = self._make_request(full_url)
            try:
                if response.text:
                    if self._is_spring_by_favicon(response) or self._is_spring_by_content(response, url):
                        return True
            except:
                logger.error("An error occurred during fingerprint matching. Procedure")
        logger.info(f"{url} is not a Spring application.")
        return False

    @staticmethod
    def _is_spring_by_favicon(response):
        try:
            content_type = response.headers.get("Content-Type", "")
            if "image" in content_type or "octet-stream" in content_type:
                favicon_hash = hashlib.md5(response.content).hexdigest()
                if favicon_hash == FingerprintDetector.SPRING_FAVICON_HASH:
                    return True
            return False
        except:
            logger.error("response not headers")

    @staticmethod
    def _is_spring_by_content(response, url):
        if 'Whitelabel Error Page' in response.text:
            logger.info(f"{url} is a Spring application.")
            return True
        return False

    def _make_request(self, url):
        """
        向指定的URL发起请求并返回响应。
        """
        try:
            response = requests.get(url, headers=DEFAULT_HEADER, proxies=self.proxy, timeout=10, verify=False)
            logger.debug(response.status_code)
            logger.debug(response.headers)
            if response.status_code in [200, 404] and response.text:
                logger.debug(response.text)
                return response
        except requests.ConnectionError as e:
            logger.error(f"URL: {url} 连接错误：{e}")
        except requests.Timeout as e:
            logger.error(f"URL: {url} 请求超时：{e}")
        except requests.RequestException as e:
            logger.error(f"URL: {url} 请求出错：{e}")
        return None
