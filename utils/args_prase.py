#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     args_prase.py
   Description :
   Author :       sule01u
   date：          2023/10/9
"""
import click
from typing import List, Dict, Optional, Union
from utils.format_utils import FormatterUtils
from utils.logging_config import configure_logger

logger = configure_logger(__name__)


class ArgumentParser:
    def __init__(self, url: Optional[str], file: Optional[str], proxy: Optional[str], threads: int):
        self.url = url
        self.file = file
        self.proxy = proxy
        self.threads = threads
        self.format_util = FormatterUtils()

    @staticmethod
    def raise_value_error(message: str) -> None:
        """抛出值错误并记录日志"""
        logger.error(message)
        raise ValueError(message)

    def validate_url_file(self) -> None:
        """验证URL和文件参数是否有效"""
        if not self.url and not self.file:
            self.raise_value_error("Usage: python3 sbscan.py -h/--help")

        if self.url and self.file:
            self.raise_value_error("Both URL and file arguments cannot be provided simultaneously. Please provide only one.")

    def get_formatted_proxy(self) -> Dict[str, str]:
        """获取格式化后的代理信息"""
        if not self.proxy:
            logger.debug("Unspecified proxy")
            return {}
        formatted_proxy = self.format_util.format_proxy(self.proxy)
        if not formatted_proxy:
            self.raise_value_error("Invalid Proxy provided. Exiting...")
        return formatted_proxy

    @staticmethod
    def extract_urls_from_file(file_path: str) -> List[str]:
        """从文件中提取URLs"""
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]

    def validate_and_format_urls(self, raw_urls: List[str]) -> List[str]:
        """验证并格式化一系列URLs"""
        valid_urls = []
        invalid_urls = []

        for url in raw_urls:
            formatted_url = self.format_util.format_url(url)
            if formatted_url:
                valid_urls.append(formatted_url)
            else:
                invalid_urls.append(url)

        if invalid_urls:
            logger.debug("A url that does not match the expected format was detected.")
            click.secho("[-] 以下URLs无效[The following URLs are in invalid format]:", fg='yellow')
            for invalid_url in invalid_urls:
                click.secho(invalid_url, fg='yellow')

        if not valid_urls:
            logger.error("No valid URLs provided in file to scan. Exiting...")
            raise ValueError("No valid URLs provided in file to scan. Exiting...")

        return valid_urls

    def extract_and_validate_urls(self) -> List[str]:
        """从URL或文件中提取并验证URLs"""
        raw_urls = []

        if self.url:
            raw_urls.append(self.url)

        if self.file:
            raw_urls.extend(self.extract_urls_from_file(self.file))

        return self.validate_and_format_urls(raw_urls)

    def parse_and_validate(self) -> Dict[str, Union[List[str], Dict[str, str], int]]:
        """解析和验证所有参数"""
        self.validate_url_file()
        formatted_proxy = self.get_formatted_proxy()
        urls = self.extract_and_validate_urls()

        logger.debug(f"return args is: %s", {
            "urls": urls,
            "proxy": formatted_proxy,
            "threads": self.threads
        }, extra={"target": urls})

        return {
            "urls": urls,
            "proxy": formatted_proxy,
            "threads": self.threads
        }


if __name__ == '__main__':
    c1 = ArgumentParser("", "../url.txt", None, 1)
    c2 = ArgumentParser("baidu.com", "", None, 1)
    print(c1.parse_and_validate())
    print(c2.parse_and_validate())
