#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     config_loader.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import json
from utils.logging_config import configure_logger
logger = configure_logger(__name__)


class ConfigLoader:
    @staticmethod
    def load_config(file_path):
        """
        从给定的文件路径加载配置
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                logger.info(f"{file_path} loading succcess!")
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error loading config from {file_path}. Error: {e}")
            return None
