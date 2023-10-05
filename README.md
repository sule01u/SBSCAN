# ✈️ 一、工具概述
扫描Spring Boot的敏感信息泄露路径是否开放并对站点测试Spring相关的漏洞。

## 🏂 Run
```Bash
$ git clone https://github.com/sule01u/SBSCAN.git
$ cd SBSCAN
$ php3 install -r requirements.txt
$ python3 sbscan.py --help
```
>  ![sbsscan](https://p.ipic.vip/t752lu.png)

fir 

## 🎡 Options
```Bash
      -u, --url TEXT     对单个URL进行扫描
      -f, --file TEXT    读取文件中的url目标进行扫描
      -p, --proxy TEXT   指定HTTP代理
      --threads INTEGER  指定线程数量
      --help             显示帮助信息

```

## 🎨 Examples
```Bash
$ python3 sbscan.py -u http://test.com
$ python3 sbscan.py -f url.txt
$ python3 sbscan.py -u http://test.com -p 1.1.1.1:8888 --threads 10
```

## ⛪ Discussion
* Dismap Bug 反馈或新功能建议[点我](https://github.com/sule01u/SBSCAN/issues)
* WeChat: 扫码关注不懂安全
<p>
    <img alt="QR-code" src="https://github.com/sule01u/BigTree975.github.io/blob/master/img/mine.png" width="20%" height="20%" style="max-width:100%;">
</p>
