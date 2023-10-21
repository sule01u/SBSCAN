#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     args_prase.py
   Description :
   Author :       sule01u
   date：          2023/10/9
"""
import click
from utils.format_utils import format_url, format_proxy
from utils.logging_config import configure_logger
logger = configure_logger(__name__)


def parse_and_validate_args(url, file, proxy, threads):
    """
    cli参数解析
    """
    if not url and not file:
        raise ValueError("Usage: python3 sbscan.py --help")

    if url and file:
        raise ValueError("Both URL and file arguments cannot be provided simultaneously. Please provide only one.")

    if proxy:
        # 存在代理配置时，代理格式化失败抛出异常
        formated_proxy = format_proxy(proxy)
        if not formated_proxy:
            logger.error("Invalid Proxy provided. Exiting...")
            raise ValueError("Invalid Proxy provided. Exiting...")
    else:
        logger.info("Unspecified proxy")
        formated_proxy = {}

    urls = []
    invalid_urls = []

    if url:
        formatted_url = format_url(url)
        if not formatted_url:
            logger.error("Invalid URL provided. Exiting...")
            raise ValueError("Invalid URL provided. Exiting...")
        urls.append(formatted_url)

    if file:
        with open(file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                formatted_url = format_url(line.strip())
                if not formatted_url:
                    invalid_urls.append(line.strip())
                else:
                    urls.append(formatted_url)

    if not urls:
        logger.error("No valid URLs provided in file to scan. Exiting...")
        raise ValueError("No valid URLs provided in file to scan. Exiting...")

    if invalid_urls:
        logger.info("The url file has an unrecognized URL")
        click.secho("The following URLs are invalid:", fg='yellow')
        for inv_url in invalid_urls:
            click.secho(inv_url, fg='yellow')

    logger.info(f"return args: %s" % {
        "urls": urls,
        "proxy": formated_proxy,
        "threads": threads
    })
    return {
        "urls": urls,
        "proxy": formated_proxy,
        "threads": threads
    }
