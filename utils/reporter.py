#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     repoter.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import os
import threading
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.box import ROUNDED
from io import StringIO
from utils.logging_config import configure_logger
logger = configure_logger(__name__)


class ReportGenerator:
    def __init__(self, output_folder='reports', quiet=False, pbar=None):
        self.quiet = quiet
        self.report_data = []
        self.output_folder = output_folder
        self.console = Console()
        self.pbar = pbar  # 接收 tqdm 进度条对象
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)
        self.lock = threading.Lock()

    def generate(self, url, is_spring, detected_paths, found_cves):
        report_entry = {
            'url': url,
            'is_spring': is_spring,
            'detected_paths': detected_paths,
            'found_cves': found_cves
        }
        if (self.quiet and (detected_paths or found_cves)) or not self.quiet:
            self._display_report(url, is_spring, detected_paths, found_cves)
            with self.lock:  # Locking only when adding to shared list
                self.report_data.append(report_entry)

    def _display_report(self, url, is_spring, paths, cves):
        table = Table(show_header=True, header_style="bold magenta", box=ROUNDED)
        table.add_column("URL", style="cyan")
        table.add_column("IS_SPRING", style="cyan")
        table.add_column("Detected Paths", style="green")
        table.add_column("Detected CVEs", style="red")

        cve_str = "\n".join([cve['CVE_ID'] + ": " + cve['Details'] for cve in cves]) if cves else "None"
        path_str = "\n".join(paths) if paths else "None"

        table.add_row(url, str(is_spring), path_str, cve_str)

        # 创建一个新的控制台对象和一个字符串IO对象
        buffer = StringIO()
        console = Console(file=buffer, force_terminal=True)  # force_terminal确保输出仍然是彩色的

        # 使用新的控制台对象输出表格
        console.print(table)

        # 获取字符串IO对象的内容
        output = buffer.getvalue()

        # 如果有 tqdm 对象，使用 tqdm.write 方法
        if self.pbar:
            self.pbar.write(output)
        else:
            self.console.print(output)  # 使用默认的控制台输出

        buffer.close()  # 关闭字符串IO对象

    def save_report_to_file(self):
        with self.lock:  # Locking while reading shared data
            if not self.report_data:
                logger.warning("没有生成任何报告内容。")
                return

            timestamp = datetime.now().strftime('%Y%m%d_%H%M')
            filename = os.path.join(self.output_folder, f'report_{timestamp}.json')
            with open(filename, 'w') as file:
                json.dump(self.report_data, file, indent=4)
            self.console.print(f"报告已保存到 [bold cyan]{filename}[/bold cyan]")

    def get_report_data(self):
        with self.lock:  # Locking while reading shared data
            return self.report_data.copy()
