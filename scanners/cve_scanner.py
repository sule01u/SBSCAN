#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_scanner.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
from tqdm import tqdm
from utils.logging_config import configure_logger
logger = configure_logger(__name__)


class CVE_Scanner:
    def __init__(self, cve_data, proxy_manager):
        # 加载cve.json中的配置
        self.cve_data = cve_data
        self.proxy = proxy_manager.get_proxy()

    def scan(self, url):
        """
        扫描指定的URL以寻找CVE漏洞。
        """
        found_cves = []
        for cve_key, cve_value in tqdm(self.cve_data.items(), desc=f"Start CVE Scanning for {url}", ncols=100, leave=False):
            # 检查is_poc字段是否为"true"
            if cve_value.get("is_poc") != "true":
                continue

            # 使用cve_key检查是否存在相应的CVE扫描模块
            module_name = f"scanners.cve_scanners.{cve_key}"
            try:
                cve_module = __import__(module_name, fromlist=["check"])
                is_vulnerable, details = cve_module.check(url, self.proxy)
                if is_vulnerable:
                    found_cves.append(details)
            except ImportError:
                logger.error(f"No CVE scanning module found for {cve_key}")
            except Exception as e:
                logger.error(f"Error during scanning for {cve_key}. Error: {e}")

        return found_cves
