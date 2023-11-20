#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     sbscan.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import sys
import signal
import locale
from click import Command, Context
import click
from managers.proxy_manager import ProxyManager
from managers.scanner_manager import ScannerManager
from utils.logging_config import configure_logger
from utils.args_prase import ArgumentParser
from utils.banner import banner, help_info_en, help_info_zh
logger = configure_logger(__name__)

system_lang = locale.getlocale()[0]


@click.command(add_help_option=False)
@click.option("-u", "--url", type=str, help="对单个URL进行扫描")
@click.option("-f", "--file", help="读取文件中的url进行扫描", type=click.Path(exists=True))
@click.option("-m", "--mode", type=str, help="扫描模式选择: [path/cve/all], 默认all", default="all")
@click.option("-p", "--proxy", type=str, help="指定HTTP代理")
@click.option("-t", "--threads", type=int, help="并发线程数, 默认单线程", default=1)
@click.option("-ff", "--fingerprint_filter", is_flag=True, help="只对存在spring指纹的网站开始扫描")
@click.option("-d", "--dnslog", type=str, help="指定dnslog域名", default="")
@click.option("-q", "--quiet", is_flag=True, help="纯净版输出，仅输出命中的结果")
@click.option("-h", "--help", is_flag=True, callback=lambda ctx, param, value: ctx.exit(click.secho(help_info_zh if system_lang.startswith("zh_CN") else help_info_en, fg='cyan') or 0) if value else None, expose_value=False, help="显示帮助信息")
def main(url, file, mode, proxy, dnslog, threads, fingerprint_filter, quiet):
    try:
        # 参数解析与验证
        args_parser = ArgumentParser(url, file, proxy, threads)
        args_data = args_parser.parse_and_validate()
        logger.debug(args_data)
        # 代理管理
        proxy_manager = ProxyManager(args_data["proxy"])
        # 扫描管理
        manager = ScannerManager(args_data["urls"], mode, proxy_manager, dnslog, args_data["threads"], fingerprint_filter, quiet)
        click.secho("[+] 扫描时间部分情况下可能稍长，请耐心等待扫描结果[Please wait for the scan results]:", fg='green', bold=True)
        logger.info("Starting scan for target URLs")
        report_data = manager.start_scanning()
        logger.info("Scan completed for target URLs")
        # 报告处理
        if quiet and not report_data:
            click.secho("[-] 目标未命中任何检测规则 [No sensitive paths or CVEs detected for the provided URLs]", fg="yellow")
        manager.reporter.save_report_to_file()
    except KeyboardInterrupt:
        click.secho("[-] 用户终止扫描 [User aborted the scan]", fg="yellow")
        sys.exit()
    except Exception as e:
        logger.error(e, extra={'url': "target_url"})
        sys.exit()


if __name__ == "__main__":
    banner()
    main()
