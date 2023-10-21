#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     concurrency_manager.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logging_config import configure_logger
logger = configure_logger(__name__)


class ConcurrencyManager:
    def __init__(self, thread_count):
        if not isinstance(thread_count, int) or thread_count <= 0:
            raise ValueError("thread_count must be a positive integer.")
        self.thread_count = thread_count

    def execute_tasks(self, task_func, urls, pbar=None):  # 添加pbar参数
        results = []
        with ThreadPoolExecutor(max_workers=self.thread_count, thread_name_prefix='Daemon') as executor:
            futures = [executor.submit(task_func, url, pbar) for url in urls]  # 为每个任务传递pbar
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Generated an exception: {e}")
        return results
