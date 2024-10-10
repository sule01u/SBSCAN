#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     proxy_manager.py
   Description :   代理管理模块，引入代理池和动态代理切换机制
   Author :       sule01u
   date：          2023/10/8
"""
import random
import requests
from itertools import cycle
from utils.custom_headers import DEFAULT_HEADER, TIMEOUT
from utils.logging_config import configure_logger

# 常量配置
TEST_URL = "https://www.baidu.com/"  # 用于测试代理可用性的 URL
DEFAULT_TIMEOUT = 5  # 代理可用性测试的默认超时时间

# 初始化日志记录
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()


class ProxyManager:
    """代理管理类，支持多代理池和动态代理切换"""
    def __init__(self, proxies=None):
        """
        初始化代理管理器
        :param proxies: 可选的代理列表或单个代理配置，格式如：
                        {"http": "http://user:password@host:port", "https": "http://user:password@host:port"}
                        或 ["http://user:password@host:port", "http://user:password@host:port"]
        """
        # 初始化代理池
        self.proxy_pool = self._init_proxy_pool(proxies)
        # 创建代理轮询器
        self.proxy_cycle = cycle(self.proxy_pool) if self.proxy_pool else None
        self.current_proxy = None

        # 初始化第一个可用代理（仅在代理池不为空时）
        if self.proxy_pool:
            self.current_proxy = self._get_next_proxy()

    def _init_proxy_pool(self, proxies):
        """
        初始化代理池
        :param proxies: 传入的代理列表或单个代理配置
        :return: 格式化后的代理池列表
        """
        if not proxies:
            return []

        # 如果传入的是字典格式的单一代理，转换为列表
        if isinstance(proxies, dict):
            proxies = [proxies]

        # 如果传入的是字符串格式的代理地址，转换为标准的代理格式
        formatted_proxies = []
        for proxy in proxies:
            formatted_proxy = self._format_proxy(proxy)
            if formatted_proxy:
                formatted_proxies.append(formatted_proxy)
        return formatted_proxies

    @staticmethod
    def _format_proxy(proxy):
        """
        格式化单个代理配置为 requests 可用的代理格式
        :param proxy: 代理地址字符串或字典格式
        :return: 格式化后的代理字典
        """
        if isinstance(proxy, str):
            # 如果是字符串格式的代理地址，统一转换为字典格式
            return {"http": proxy, "https": proxy}
        elif isinstance(proxy, dict):
            return proxy
        return None

    def _get_next_proxy(self):
        """
        获取下一个可用代理
        :return: 下一个可用代理的字典格式
        """
        if not self.proxy_cycle:
            return None

        for _ in range(len(self.proxy_pool)):
            proxy = next(self.proxy_cycle)
            if self._is_proxy_working(proxy):
                logger.info(f"Switched to new working proxy: {proxy}")
                return proxy
        logger.warning("No available proxy in the pool.")
        return None

    def _is_proxy_working(self, proxy):
        """
        检测代理是否可用
        :param proxy: 待检测的代理配置
        :return: True - 代理可用, False - 代理不可用
        """
        try:
            response = requests.get(TEST_URL, headers=DEFAULT_HEADER, proxies=proxy, timeout=DEFAULT_TIMEOUT, verify=False)
            if response.status_code == 200:
                return True
        except requests.RequestException:
            logger.warning(f"Proxy {proxy} is not available.")
        return False

    def get_proxy(self):
        """
        获取当前可用的代理配置
        :return: 当前可用代理的字典格式，如果代理池为空，则返回 None
        """
        # 如果代理池为空，则返回 None，不做任何代理切换
        if not self.proxy_pool:
            return None

        if not self.current_proxy or not self._is_proxy_working(self.current_proxy):
            logger.warning(f"Current proxy is not available, switching to next proxy...")
            self.current_proxy = self._get_next_proxy()
        return self.current_proxy

    def get_random_proxy(self):
        """
        随机获取一个可用代理（从代理池中随机选择）
        :return: 随机选择的代理配置
        """
        if not self.proxy_pool:
            return None
        return random.choice(self.proxy_pool)


if __name__ == '__main__':
    # 测试用例
    proxies = [
        "http://user:password@host1:port1",
        "http://user:password@host2:port2",
        {"http": "http://user:password@host3:port3", "https": "http://user:password@host3:port3"}
    ]
    proxy_manager = ProxyManager(proxies)
    print("Current Proxy:", proxy_manager.get_proxy())  # 获取当前可用代理
    print("Random Proxy:", proxy_manager.get_random_proxy())  # 获取随机代理