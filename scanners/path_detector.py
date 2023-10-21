#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     path_detector.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import requests
from tqdm import tqdm
from utils.logging_config import configure_logger
logger = configure_logger(__name__)


class PathDetector:
    MAX_FAILED_COUNT = 50
    CHUNK_SIZE = 1024
    SSE_MAX_SIZE = 2048

    def __init__(self, paths, proxy_manager):
        self.paths = paths
        self.proxy = proxy_manager.get_proxy()

    def detect(self, url):
        """
        敏感路径检测
        """
        path_failed_count = 0
        detected_paths = []
        for path, signature in self.paths.items():
            if path_failed_count > self.MAX_FAILED_COUNT:
                break
            full_url = url + path
            response = self._make_request(full_url)
            if response:
                if signature.lower() in response.lower():
                    detected_paths.append(full_url)
            else:
                path_failed_count += 1

        return detected_paths

    def _make_request(self, url):
        try:
            with requests.get(url, verify=False, proxies=self.proxy, timeout=10, stream=True) as response:
                if "text/event-stream" not in response.headers.get("Content-Type", ""):
                    if response.status_code == 200:
                        return response.text
                else:  # 如果是SSE，读取前2048字节，然后断开连接
                    content = b""
                    for chunk in response.iter_content(self.CHUNK_SIZE):
                        content += chunk
                        if len(content) > 2048:
                            break
                    return content.decode("utf-8")
        except requests.ConnectionError as e:
            logger.error(f"URL: {url} Connection error: {e}")
        except requests.Timeout as e:
            logger.error(f"URL: {url} Request timeout: {e}")
        except requests.RequestException as e:
            logger.error(f"URL: {url} Request error: {e}")
        except Exception as e:
            logger.error(f"URL: {url} Error detection: {e}")
        return None

    def _is_valid_response(self, response):
        """
        进一步验证找到的敏感路径的响应内容。
        基于响应长度进行验证，添加其他逻辑，如检查特定的响应头或响应体内容。
        """
        return 100 < len(response.text) < 10000
