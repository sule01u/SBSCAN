#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     scanner_manager.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
from tqdm import tqdm
from scanners.path_detector import PathDetector
from scanners.cve_scanner import CVE_Scanner
from scanners.fingerprint_detector import FingerprintDetector
from managers.concurrency_manager import ConcurrencyManager
from utils.config_loader import ConfigLoader
from utils.reporter import ReportGenerator
from utils.logging_config import configure_logger
logger = configure_logger(__name__)


class ScannerManager:
    def __init__(self, target_urls, proxy_manager, dns_domain, max_threads, fingerprint_filter=False, quiet=False):
        self.target_urls = target_urls
        self.proxy_manager = proxy_manager
        self.dns_domain = dns_domain
        self.max_threads = max_threads
        self.quiet = quiet
        self.fingerprint_filter = fingerprint_filter

        # 创建Path扫描器的实例
        paths_config = ConfigLoader.load_config("config/path.json")
        self.path_detector = PathDetector(paths_config, self.proxy_manager)

        # 创建CVE扫描器的实例
        cve_config = ConfigLoader.load_config("config/cve.json") or {}
        self.cve_scanner = CVE_Scanner(cve_config, self.proxy_manager)

    def start_scanning(self):
        try:
            pbar = tqdm(total=len(self.target_urls), desc="Start Scanning: ", ncols=100)
            # 此处初始化ReportGenerator
            self.reporter = ReportGenerator(quiet=self.quiet, pbar=pbar)
            concurrency_manager = ConcurrencyManager(thread_count=self.max_threads)
            concurrency_manager.execute_tasks(self.scan_url, self.target_urls, pbar)  # 将pbar作为参数传递
            pbar.close()  # 关闭进度条
            return self.reporter.get_report_data()
        except KeyboardInterrupt:
            raise
        except Exception:
            pbar.close()
            raise

    def scan_url(self, url, pbar=None):
        logger.debug(f"Starting scan target", extra={"target": url})
        detected_paths = []
        found_cves = []
        try:
            if self.fingerprint_filter:
                # 指纹检测
                fingerprint_detector = FingerprintDetector(self.proxy_manager)
                is_spring = fingerprint_detector.is_spring_app(url)
                if not is_spring:
                    self.reporter.generate(url, is_spring, detected_paths, found_cves)
                    logger.debug(f"current url completed scan", extra={"target": url})
                    if pbar:  # 更新进度条
                        pbar.update(1)
                    return
            else:
                is_spring = None

            # 敏感路径检测
            detected_paths = self.path_detector.detect(url)
            if detected_paths:
                logger.info(f"Detected {len(detected_paths)} sensitive paths", extra={"target": url})
            else:
                logger.info(f"No sensitive paths detected", extra={"target": url})

            # CVE扫描
            found_cves = self.cve_scanner.scan(url, self.dns_domain)
            if not found_cves:
                logger.info(f"No CVE vulnerabilities detected", extra={"target": url})

            # 生成报告
            self.reporter.generate(url, is_spring, detected_paths, found_cves)
            if pbar:  # 更新进度条
                pbar.update(1)
            logger.debug(f"current url completed scan", extra={"target": url})
        except Exception as e:
            logger.error(f"An error occurred while processing URL: {str(e)}", extra={"target": url})
