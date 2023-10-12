#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     concurrency_manager.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logging_config import configure_logger
logger = configure_logger(__name__)


class ConcurrencyManager:
    def __init__(self, thread_count=10):
        self.thread_count = thread_count

    def execute_tasks(self, task_func, items):
        results = []
        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            futures = [executor.submit(task_func, item) for item in items]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as exc:
                    logger.error(f"Generated an exception: {exc}")
        return results
