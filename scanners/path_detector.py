#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     path_detector.py
   Description :   路径检测模块，提高了路径探测速度和效率
   Author :       sule01u
   date：          2023/10/8
"""

import time
import requests
from urllib.parse import urljoin
from concurrent.futures import as_completed
from utils.custom_headers import TIMEOUT, DEFAULT_HEADER
from utils.logging_config import configure_logger
from utils.global_thread_pool import GlobalThreadPool  # 引入全局线程池
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading

# 初始化日志记录
logger = configure_logger(__name__)

class PathDetector:
    """路径探测类"""
    MAX_FAILED_COUNT = 80
    MAX_SUCCESS_COUNT = 80
    CHUNK_SIZE = 1024
    SSE_MAX_SIZE = 5120  # 5KB
    MAX_RESPONSE_LENGTH = 102400  # 100KB

    def __init__(self, paths, proxy_manager):
        self.paths = paths
        self.proxy = proxy_manager.get_proxy()
        self.thread_local = threading.local()  # 创建线程本地存储

    def detect(self, url):
        """检测指定URL的敏感路径"""
        path_failed_count = 0
        path_success_count = 0
        detected_paths = []
        try:
            # 使用全局线程池进行并发探测
            futures = {GlobalThreadPool.submit_task(self._detect_path, url, path, signature): path for path, signature in self.paths.items()}

            for future in as_completed(futures):
                path = futures[future]
                try:
                    result = future.result()
                    if result:
                        detected_paths.append(result)
                        path_success_count += 1
                        logger.info(f"[Success] Detected sensitive path: {result}", extra={"target": result})

                    if path_success_count > self.MAX_SUCCESS_COUNT:
                        logger.info(f"Exceeded maximum success count of {self.MAX_SUCCESS_COUNT}, stopping path detection for {url}")
                        break

                except Exception as e:
                    path_failed_count += 1
                    logger.error(f"Error detecting path: {path} - {e}", extra={"target": url})

                if path_failed_count > self.MAX_FAILED_COUNT:
                    logger.info(f"Exceeded maximum failed count of {self.MAX_FAILED_COUNT}, stopping path detection for {url}")
                    break
                time.sleep(0.05)  # 防止过快请求导致目标被封禁
        except KeyboardInterrupt:
            logger.warning("User interrupted the path detection process with Ctrl + C")
            # 取消所有未完成的任务
            for future in futures:
                future.cancel()
            logger.info("All pending tasks were cancelled successfully.")
        finally:
            logger.info(f"Path detection process for {url} finished.")

        return detected_paths

    def _detect_path(self, url, path, signature):
        """探测单个路径是否存在"""
        full_url = urljoin(url, path)
        response_content = self._make_request(full_url)
        if response_content and signature.lower() in response_content.lower():
            return full_url
        return None

    def _make_request(self, url):
        """发起请求并返回响应内容"""
        session = self._get_session()  # 获取线程本地的 Session 对象
        try:
            with session.get(url, stream=True, allow_redirects=False) as res:
                logger.debug(f"[{res.status_code}] [Content-Length: {res.headers.get('Content-Length', 0)}]", extra={"target": url})
                if "text/event-stream" in res.headers.get("Content-Type", ""):
                    # SSE 流式传输处理
                    content = b""
                    for chunk in res.iter_content(self.CHUNK_SIZE):
                        content += chunk
                        if len(content) > self.SSE_MAX_SIZE:
                            break
                    return content.decode("utf-8", errors="ignore")
                elif res.status_code == 200:
                    # 返回前 MAX_RESPONSE_LENGTH 的内容
                    return res.text[:self.MAX_RESPONSE_LENGTH]
        except requests.RequestException as e:
            logger.debug(f"Request error: {e}", extra={"target": url})
        except Exception as e:
            logger.error(f"An unexpected error occurred during path detection: {e}", extra={"target": url})
        return None

    def _get_session(self):
        """获取线程本地的 Session 对象，如果不存在则创建"""
        if not hasattr(self.thread_local, 'session'):
            session = requests.Session()
            session.headers.update(DEFAULT_HEADER)
            session.verify = False
            session.proxies = self.proxy
            session.timeout = TIMEOUT
            session.max_redirects = 3

            # 配置 HTTPAdapter，启用 keep-alive 和连接池
            adapter = HTTPAdapter(
                pool_connections=200,
                pool_maxsize=200,
                max_retries=Retry(total=3, backoff_factor=0.3)
            )
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            self.thread_local.session = session
        return self.thread_local.session

    def __del__(self):
        """析构函数：关闭所有线程本地的 Session 对象"""
        if hasattr(self.thread_local, 'session'):
            self.thread_local.session.close()


def close_sessions(detector_instance):
    """显式关闭所有线程的 Session 对象"""
    if hasattr(detector_instance.thread_local, 'session'):
        detector_instance.thread_local.session.close()


if __name__ == '__main__':
    # 测试用例
    from managers.proxy_manager import ProxyManager

    # 初始化全局线程池
    GlobalThreadPool.initialize(max_workers=50)  # 新增：初始化全局线程池

    proxy_manager = ProxyManager()
    paths = {"actuator": "_links", "actuator/beans": "beans"}
    path_d = PathDetector(paths, proxy_manager)
    print(path_d.detect("http://192.168.1.13:8080/"))