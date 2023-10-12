#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     scanner_manager.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
from rich import print
import requests
from scanners.path_detector import PathDetector
from scanners.cve_scanner import CVE_Scanner
from scanners.fingerprint_detector import FingerprintDetector
from utils.config_loader import ConfigLoader
from utils.reporter import ReportGenerator
from utils.logging_config import configure_logger
logger = configure_logger(__name__)


class ScannerManager:
    def __init__(self, target_urls, proxy_manager, max_threads=10, fingerprint_filter=False, quiet=False):
        self.target_urls = target_urls
        self.proxy_manager = proxy_manager
        self.max_threads = max_threads
        self.quiet = quiet
        self.fingerprint_filter = fingerprint_filter
        self.reporter = ReportGenerator(quiet=quiet)

        # 创建Path扫描器的实例
        paths_config = ConfigLoader.load_config("config/path.json")
        self.path_detector = PathDetector(paths_config, self.proxy_manager)

        # 创建CVE扫描器的实例
        cve_config = ConfigLoader.load_config("config/cve.json") or {}
        self.cve_scanner = CVE_Scanner(cve_config, self.proxy_manager)

    def start_scanning(self):
        for url in self.target_urls:
            logger.info(f"Starting scan for {url}")
            try:
                if self.fingerprint_filter:
                    # 指纹检测
                    fingerprint_detector = FingerprintDetector(self.proxy_manager)
                    is_spring = fingerprint_detector.is_spring_app(url)
                    if not is_spring:
                        self.reporter.generate(url, is_spring, [], [])
                        logger.info(f"Completed scan for {url}")
                        continue
                else:
                    is_spring = None

                # 敏感路径检测
                detected_paths = self.path_detector.detect(url)
                if detected_paths:
                    for path in detected_paths:
                        logger.info(f"Detected path {path} for {url}")
                else:
                    logger.info(f"No sensitive paths detected for {url}")

                # CVE扫描
                found_cves = self.cve_scanner.scan(url)
                if found_cves:
                    for cve in found_cves:
                        logger.info(f"Detected {cve['CVE_ID']} for {url}")
                else:
                    logger.info(f"No CVE vulnerabilities detected for {url}")

                # 报告
                self.reporter.generate(url, is_spring, detected_paths, found_cves)
                logger.info(f"Completed scan for {url}")
            except requests.RequestException as e:
                logger.error(f"处理URL {url} 时发生错误: {str(e)}")

        return self.reporter.get_report_data()

    # @staticmethod
    # def from_file(file_path, proxies=None, max_threads=10):
    #     with open(file_path, 'r') as f:
    #         urls = [line.strip() for line in f.readlines()]
    #     return ScannerManager(urls, proxies, max_threads)
