#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     banner.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import random
from rich.console import Console

console = Console()


def banner():
    colors = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]

    LOGO = [
        r"             _",
        r"_   _ _ __ | | ___ __   _____      ___ __        ___  ___  ___",
        r"| | | | '_ \| |/ / '_ \ / _ \ \ /\ / / '_ \ _____/ __|/ _ \/ __|",
        r"| |_| | | | |   <| | | | (_) \ V  V /| | | |_____\__ \  __/ (__",
        r"\__,_|_| |_|_|\_\_| |_|\___/ \_/\_/ |_| |_|     |___/\___|\___|",
        "",
        r"name: SBSCAN",
        r"author: sule01u",
        r"from: [underline]https://github.com/sule01u/SBSCAN[/underline]",
        r"desc: springboot information leak scanning & spring vulnerability scanning",
        r""
        ""
    ]

    for line in LOGO:
        color = random.choice(colors)
        console.print(line, style=f"{color}")
