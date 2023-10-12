#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     logging_config.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import logging
import os

LOG_LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s'

# 项目统一的日志配置
DEFAULT_LOG_LEVEL = "error"
DEFAULT_OUTPUT_MODE = 'file'


def configure_logger(name, level=None, output_mode=None):
    """
    配置日志器并返回一个日志实例
    """

    # 如果为单个脚本没有设置配置，则使用项目的统一配置
    log_level = level if level else DEFAULT_LOG_LEVEL
    log_output_mode = output_mode if output_mode else DEFAULT_OUTPUT_MODE

    # Ensure that the logging directory exists
    if not os.path.exists('logs'):
        os.makedirs('logs')

    logger = logging.getLogger(name)
    logger.setLevel(LOG_LEVELS.get(log_level, logging.INFO))
    logger.propagate = False

    formatter = logging.Formatter(LOG_FORMAT)

    # Configure console logging
    if log_output_mode in ('console', 'both'):
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Configure file logging
    if log_output_mode in ('file', 'both'):
        file_handler = logging.FileHandler('logs/sbscan.log')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
