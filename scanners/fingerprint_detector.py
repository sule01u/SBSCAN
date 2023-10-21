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
from urllib.parse import urljoin
from utils.custom_headers import DEFAULT_HEADER
from utils.logging_config import configure_logger

logger = configure_logger(__name__)


class FingerprintDetector:
    SPRING_FAVICON_HASH = "0488faca4c19046b94d07c3ee83cf9d6"
    PATHS = ["/favicon.ico", "/"]

    def __init__(self, proxy_manager):
        self.proxy = proxy_manager.get_proxy()

    def is_spring_app(self, url):
        """检测目标站点是否使用Spring框架"""
        for path in self.PATHS:
            full_url = urljoin(url, path)
            logger.debug(full_url)
            response = self._make_request(full_url)
            logger.debug(response.text)
            try:
                if response.text and (self._is_spring_by_favicon(response) or self._is_spring_by_content(response) or self._is_spring_by_header(response)):
                    logger.info(f"{url} is a Spring application.")
                    return True
            except AttributeError as e:
                logger.error(f"Error while request {full_url}: {e}")
        logger.info(f"{url} is not a Spring application.")
        return False

    @staticmethod
    def _is_spring_by_favicon(response):
        """通过favicon判断是否为Spring应用"""
        content_type = response.headers.get("Content-Type", "")
        if "image" in content_type or "octet-stream" in content_type:
            favicon_hash = hashlib.md5(response.content).hexdigest()
            return favicon_hash == FingerprintDetector.SPRING_FAVICON_HASH
        return False

    @staticmethod
    def _is_spring_by_content(response):
        """通过内容判断是否为Spring应用"""
        return 'Whitelabel Error Page' in response.text

    @staticmethod
    def _is_spring_by_header(response):
        """通过响应头判断是否为Spring应用"""
        return "X-Application-Context" in response.headers

    def _make_request(self, url):
        """向指定的URL发起请求并返回响应。"""
        try:
            response = requests.get(url, headers=DEFAULT_HEADER, proxies=self.proxy, timeout=10, verify=False)
            if response.content:
                return response
        except requests.ConnectionError as e:
            logger.error(f"URL: {url} Connection error: {e}")
        except requests.Timeout as e:
            logger.error(f"URL: {url} Request timed out: {e}")
        except requests.RequestException as e:
            logger.error(f"URL: {url} Request error: {e}")
        except Exception as e:
            logger.error(f"URL: {url} Error detection: {e}")
        return None
