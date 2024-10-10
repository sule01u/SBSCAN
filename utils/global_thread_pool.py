#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     global_thread_pool.py
   Description :   全局线程池管理类，提升了多线程执行效率
   Author :       sule01u
   date：          2023/10/8
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logging_config import configure_logger

# 初始化日志记录
logger = configure_logger(__name__)


class GlobalThreadPool:
    """
    全局线程池管理类，提供线程池的全局实例，以便在整个程序中共享同一个线程池。
    """
    _executor = None

    @classmethod
    def initialize(cls, max_workers=50):
        """初始化全局线程池"""
        if cls._executor is None:
            cls._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='GlobalPool')
            logger.info(f"Initialized global thread pool with {max_workers} threads.")

    @classmethod
    def get_executor(cls):
        """获取全局线程池实例"""
        if cls._executor is None:
            raise RuntimeError("GlobalThreadPool not initialized. Call 'initialize' first.")
        return cls._executor

    @classmethod
    def submit_task(cls, func, *args, **kwargs):
        """提交任务到全局线程池执行"""
        executor = cls.get_executor()
        return executor.submit(func, *args, **kwargs)

    @classmethod
    def execute_tasks(cls, task_func, urls, pbar=None):
        """
        提交一组任务到全局线程池，并等待所有任务完成。

        :param task_func: 任务函数
        :param urls: 待处理的URL列表
        :param pbar: tqdm进度条对象
        """
        executor = cls.get_executor()
        futures = {executor.submit(task_func, url, pbar): url for url in urls}
        results = []
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logger.error(f"Generated an exception: {e}", extra={"target": futures[future]})
        return results

    @classmethod
    def shutdown(cls, wait=True):
        """关闭全局线程池"""
        if cls._executor:
            logger.info("Shutting down global thread pool.")
            cls._executor.shutdown(wait=wait)
            cls._executor = None