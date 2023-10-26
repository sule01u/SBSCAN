#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_scanner.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
from utils.logging_config import configure_logger

logger = configure_logger(__name__)


class CVEScanner:
    def __init__(self, cve_data, proxy_manager):
        # 加载cve.json中的配置
        self.cve_data = cve_data
        self.proxy = proxy_manager.get_proxy()

    @staticmethod
    def _scan_cve(cve_key, url, dns_domain, proxy):
        """对单一CVE进行扫描"""
        module_name = f"scanners.cve_scanners.{cve_key}"
        try:
            cve_module = __import__(module_name, fromlist=["check"])
            is_vulnerable, details = cve_module.check(url, dns_domain, proxy)
            if is_vulnerable:
                return details
        except ImportError:
            logger.error(f"No CVE scanning module found for {cve_key}")
        except Exception as e:
            logger.error(f"Error during scanning for {cve_key}. Error: {e}")
        return None

    def scan(self, url, dns_domain):
        """
        扫描指定的URL以寻找CVE漏洞。
        """
        found_cves = []
        for cve_key, cve_value in self.cve_data.items():
            # 检查is_poc字段是否为"true"
            if cve_value.get("is_poc") != "true":
                continue

            cve_details = self._scan_cve(cve_key, url, dns_domain, self.proxy)
            if cve_details:
                found_cves.append(cve_details)
                break

        return found_cves


if __name__ == '__main__':
    from utils.config_loader import ConfigLoader
    from managers.proxy_manager import ProxyManager
    proxy_manager = ProxyManager()
    cve_config = ConfigLoader.load_config("../config/cve.json") or {}
    c1 = CVEScanner(cve_config, proxy_manager)
    print(c1.scan("http://192.168.1.13:8080/", ""))
