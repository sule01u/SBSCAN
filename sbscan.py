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
from click import Command, Context
import click
from managers.proxy_manager import ProxyManager
from managers.scanner_manager import ScannerManager
from utils.logging_config import configure_logger
from utils.args_prase import parse_and_validate_args
logger = configure_logger(__name__)


class CustomCommand(Command):
    def format_usage(self, ctx: Context, formatter):
        formatter.write_text("python3 sbscan.py [OPTIONS]")


@click.command(cls=CustomCommand, add_help_option=False)
@click.option("-u", "--url", type=str, help="对单个URL进行扫描")
@click.option("-f", "--file", help="读取文件中的url进行扫描", type=click.Path(exists=True))
@click.option("-p", "--proxy", type=str, help="使用HTTP代理")
@click.option("-t", "--threads", type=int, help="并发线程数, 默认单线程", default=1)
@click.option("-ff", "--fingerprint_filter", is_flag=True, help="只对存在spring指纹的网站开始扫描")
@click.option("-q", "--quiet", is_flag=True, help="纯净版输出，仅输出命中的结果")
@click.option('--help', is_flag=True, callback=lambda ctx, param, value: ctx.exit(click.echo(ctx.get_help()) or 0) if value else None, expose_value=False, help="显示帮助信息")
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

    try:
        manager = ScannerManager(args_data["urls"], proxy_manager, args_data["threads"], fingerprint_filter, quiet)
        click.secho("扫描时间部分情况下可能稍长，请耐心等待扫描结果:[Please wait for the scan results]", fg='green', bold=True)
        report_data = manager.start_scanning()
        if quiet and not report_data:
            click.secho("目标未命中检测规则 [No sensitive paths or CVEs detected for the provided URLs.]", fg="yellow")
        manager.reporter.save_report_to_file()
    except KeyboardInterrupt:
        click.secho("已手动中断扫描 [Interrupted scan].", fg='red')
        sys.exit(1)
    except Exception as e:
        logger.error(e)
        sys.exit(1)


if __name__ == "__main__":
    banner()
    main()
