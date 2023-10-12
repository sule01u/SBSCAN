#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     output.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
from rich import print


def banner():
    LOGO = r'''
             _
 _   _ _ __ | | ___ __   _____      ___ __        ___  ___  ___
| | | | '_ \| |/ / '_ \ / _ \ \ /\ / / '_ \ _____/ __|/ _ \/ __|
| |_| | | | |   <| | | | (_) \ V  V /| | | |_____\__ \  __/ (__
 \__,_|_| |_|_|\_\_| |_|\___/ \_/\_/ |_| |_|     |___/\___|\___|

 name: SBSCAN
 author: sule01u
 from: https://github.com/sule01u/SBSCAN
 desc: springboot信息泄漏扫描 & spring漏洞扫描

'''
    print(LOGO)
