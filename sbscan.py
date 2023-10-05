#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     springboot_unauthorized.py
   Description :
   Author :       sule01u
   date：          2023/10/4
"""
import click
from configs.banner import banner
from cmd.leak_scan import scan
from cmd.vul_scan.cve_manager import run_cve_checks
from cmd.proxy_check import is_proxy_working


@click.command(context_settings={"ignore_unknown_options": True})
@click.pass_context
@click.option("-u", "--url", type=str, help="对单个URL进行扫描")
@click.option("-f", "--file", type=str, help="读取文件中的url进行扫描")
@click.option("-p", "--proxy", type=str, help="使用HTTP代理")
@click.option('--threads', type=int, default=5, help='指定线程数量')
def main(ctx, url, file, proxy, threads):
    urls = []
    if proxy and not is_proxy_working(proxy):
        print(f"Proxy {proxy} is not working!")
        return
    if not any([url, file]):
        click.echo(ctx.get_help())
        return
    if url and file:
        click.echo(ctx.get_help())
        return
    if url:
        urls.append(url)
    elif file:
        with open(file, 'r') as f:
            urls = [line.strip() for line in f]
    # leak_scan
    scan(urls, proxy, threads)

    # vul_scan
    run_cve_checks(urls, proxy, threads)


if __name__ == '__main__':
    banner()
    main()
