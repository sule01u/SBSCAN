#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     repoter.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
from datetime import datetime
import os
import json
from rich import box
from rich.console import Console
from rich.table import Table
from utils.logging_config import configure_logger

logger = configure_logger(__name__)


class ReportGenerator:
    def __init__(self, output_folder='reports', quiet=False):
        self.quiet = quiet
        self.report_data = []
        self.output_folder = output_folder
        self.console = Console()
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)

    def generate(self, url, is_spring, detected_paths, found_cves):
        """
        检测报告生成
        """
        report_entry = {
            'url': url,
            'is_spring': is_spring,
            'detected_paths': detected_paths,
            'found_cves': found_cves
        }
        if (self.quiet and (detected_paths or found_cves)) or not self.quiet:
            self._display_report(url, is_spring, detected_paths, found_cves)
            self.report_data.append(report_entry)

    def _display_report(self, url, is_spring, paths, cves):
        """
        输出检测报告到控制台
        """
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("URL", style="cyan")
        table.add_column("IS_SPRING", style="cyan")
        table.add_column("Detected Paths", style="green")
        table.add_column("Detected CVEs", style="red")

        cve_str = "\n".join([cve['CVE_ID'] + ": " + cve['Details'] for cve in cves]) if cves else "None"
        path_str = "\n".join(paths) if paths else "None"

        table.add_row(url, str(is_spring), path_str, cve_str)
        self.console.print(table)

    def save_report_to_file(self):
        """
        保存检测报告到文件
        """
        if not self.report_data:
            logger.warning("没有生成任何报告内容。")
            return 

        timestamp = datetime.now().strftime('%Y%m%d_%H%M')
        filename = os.path.join(self.output_folder, f'report_{timestamp}.json')
        with open(filename, 'w') as file:
            json.dump(self.report_data, file, indent=4)
        self.console.print(f"报告已保存到 [bold cyan]{filename}[/bold cyan]")

    def get_report_data(self):
        return self.report_data
