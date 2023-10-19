# ✈️ 一、工具概述
## SBSCAN：（如果觉得还不错，想要一个🌟）
- 用于检测站点是否存在Spring Boot的敏感信息泄漏
- 用于检测站点是否存在Spring相关的漏洞

## 🏂 Run
```Bash
# 安装使用
$ git clone https://github.com/sule01u/SBSCAN.git
$ cd SBSCAN
$ pip3 install -r requirements.txt   # 以免跟其他包版本冲突，可以创建虚拟环境后安装项目依赖
$ python3 sbscan.py --help
```
> 使用效果图

![](https://p.ipic.vip/1j9o3a.png)


## 🎡 Options
```Bash
      -u, --url               				对单个URL进行扫描
      -f, --file              				读取文件中的url目标进行扫描
      -p, --proxy             				指定HTTP代理
      -t, --threads           				指定线程数量
      -q, --quiet             				启用纯净输出，只输出命中的敏感路径信息
      -ff, --fingerprint_filter                       启用指纹检测，只扫描命中指纹的站点(可能有漏报，结合实际情况选择是否启用)
      --help                  				显示帮助信息

```

## 🎨 Examples
```Bash
# 指定目标站点url进行扫描
$ python3 sbscan.py -u http://test.com
# 指定url文件路径扫描，启用指纹检测，未检测到指纹的无需进行路径以及CVE扫描
$ python3 sbscan.py -f url.txt --ff
# 指定目标站点url、代理、线程数量
$ python3 sbscan.py -u http://test.com -p 1.1.1.1:8888 -t 10
# 指定目标站点url、启用纯净输出，只输出命中敏感路径或cve的目标、启用指纹检测，只有命中指纹的才继续扫描
$ python3 sbscan.py -u http://test.com --quiet -ff
```

## ⛪ Discussion
* Bug 反馈或新功能建议[点我](https://github.com/sule01u/SBSCAN/issues)
* WeChat: 扫码关注不懂安全
* 欢迎pr
<p>
    <img alt="QR-code" src="https://github.com/sule01u/BigTree975.github.io/blob/master/img/mine.png" width="20%" height="20%" style="max-width:100%;">
</p>

## 📑 Licenses

在原有协议[LICENSE](https://github.com/sule01u/SBSCAN/blob/master/LICENSE)中追加以下免责声明。若与原有协议冲突均以免责声明为准。

本工具禁止进行未授权测试，禁止二次开发后进行未授权测试。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。
