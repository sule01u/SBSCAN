#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     proxy_manager.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import requests
from utils.logging_config import configure_logger

# Constants
TEST_URL = "https://www.baidu.com/"
TIMEOUT = 10

logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()


class ProxyManager:
    def __init__(self, proxies=None):
        self.proxy = proxies
        if self.proxy and not self._is_proxy_working():
            msg = "Proxy seems to be non-functional. Proceeding without it."
            logger.warning(msg)
            raise ConnectionError("Error: Proxy unavailable")

    def _is_proxy_working(self):
        """
        检测代理有效性
        """
        try:
            response = requests.get(TEST_URL, verify=False, proxies=self.proxy, timeout=TIMEOUT)
            if response.status_code == 200:
                logger.info("Proxy detection available")
                return True
        except requests.Timeout:
            logger.warning("Proxy connection timed out")
        except requests.ConnectionError:
            logger.warning("Error connecting through proxy")
        except requests.RequestException:
            logger.warning("Proxy connection error")
        except Exception as e:
            logger.warning("Proxy detect UnknownError: %s", e)
        return False

    def get_proxy(self):
        return self.proxy

