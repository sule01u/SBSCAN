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
from colorama import init, Fore, Back, Style

# 初始化colorama
init(autoreset=True)

# 日志级别
LOG_LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

# 项目统一的日志配置
DEFAULT_LOG_LEVEL = "info"
DEFAULT_OUTPUT_MODE = 'file'


class ColoredFormatter(logging.Formatter):
    """
    日志着色
    """
    FORMATS = {
        'DEBUG': Fore.CYAN + "[%(asctime)s] " + Fore.BLUE + "[%(levelname)s]" + Fore.CYAN + " [%(filename)s] " + Fore.YELLOW + "[%(target)s] " + Fore.BLUE + "%(message)s",
        'INFO': Fore.CYAN + "[%(asctime)s] " + Fore.GREEN + "[%(levelname)s]" + Fore.CYAN + " [%(filename)s] " + Fore.YELLOW + "[%(target)s] " + Fore.GREEN + "%(message)s",
        'WARNING': Fore.CYAN + "[%(asctime)s] " + Fore.YELLOW + "[%(levelname)s]" + Fore.CYAN + " [%(filename)s] " + Fore.YELLOW + "[%(target)s] " + Fore.YELLOW + "%(message)s",
        'ERROR': Fore.CYAN + "[%(asctime)s] " + Fore.RED + "[%(levelname)s]" + Fore.CYAN + " [%(filename)s] " + Fore.YELLOW + "[%(target)s] " + Fore.RED + "%(message)s",
        'CRITICAL': Fore.CYAN + "[%(asctime)s] " + Fore.MAGENTA + "[%(levelname)s]" + Fore.CYAN + " [%(filename)s] " + Fore.YELLOW + "[%(target)s] " + Back.RED + Fore.WHITE + "%(message)s"
    }

    def __init__(self):
        super().__init__()

    def format(self, record):
        if not hasattr(record, 'target'):
            record.target = 'N/A'  # set default value
        log_fmt = self.FORMATS.get(record.levelname)
        formatter = logging.Formatter(log_fmt, datefmt='%H:%M:%S')
        return formatter.format(record)


def configure_logger(name, level=None, output_mode=None):
    """
    配置日志器并返回一个日志实例
    """
    log_level = level if level else DEFAULT_LOG_LEVEL
    log_output_mode = output_mode if output_mode else DEFAULT_OUTPUT_MODE

    # Ensure that the logging directory exists
    if not os.path.exists('logs'):
        os.makedirs('logs')

    logger = logging.getLogger(name)
    logger.setLevel(LOG_LEVELS.get(log_level, logging.INFO))
    logger.propagate = False

    # Configure console logging
    if log_output_mode in ('console', 'both'):
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(ColoredFormatter())
        logger.addHandler(console_handler)

    # Configure file logging
    if log_output_mode in ('file', 'both'):
        file_handler = logging.FileHandler('logs/sbscan.log')
        file_handler.setFormatter(ColoredFormatter())
        logger.addHandler(file_handler)

    return logger
