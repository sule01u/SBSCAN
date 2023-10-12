#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     sbscan.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import sys
from utils.banner import banner
import click
from managers.proxy_manager import ProxyManager
from managers.scanner_manager import ScannerManager
from utils.logging_config import configure_logger
from utils.args_prase import parse_and_validate_args

logger = configure_logger(__name__)


@click.command()
@click.option("-u", "--url", type=str, help="对单个URL进行扫描")
@click.option("-f", "--file", help="读取文件中的url进行扫描", type=click.Path(exists=True))
@click.option("-p", "--proxy", type=str, help="使用HTTP代理")
@click.option("-t", "--threads", type=int, help="并发线程数。", default=5)
@click.option("-ff", "--fingerprint_filter", is_flag=True, help="只对存在spring指纹的网站开始扫描")
@click.option("-q", "--quiet", is_flag=True, help="纯净版输出，仅输出命中的结果")
def main(url, file, proxy, threads, fingerprint_filter, quiet):
    try:
        # 使用args_parse模块进行参数解析和验证
        args_data = parse_and_validate_args(url, file, proxy, threads)
    except ValueError as e:
        click.secho(str(e), fg='red')
        sys.exit(1)

    try:
        proxy_manager = ProxyManager(args_data["proxy"])
    except Exception as e:
        click.secho(str(e), fg='red')
        sys.exit(1)

    manager = ScannerManager(args_data["urls"], proxy_manager, args_data["threads"], fingerprint_filter, quiet)
    report_data = manager.start_scanning()
    if quiet and not report_data:
        click.secho("No sensitive paths or CVEs detected for the provided URLs.", fg="yellow")
    manager.reporter.save_report_to_file()


if __name__ == "__main__":
    banner()
    main()
