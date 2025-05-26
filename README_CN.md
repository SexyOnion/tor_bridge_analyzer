# Tor网桥分析脚本

## 功能

本项目包含一个Python脚本，运行这个脚本将会下载最新版本的GeoLite数据库，并且会下载获取到的Tor网桥列表。然后，脚本将会通过GeoLite数据库解析Tor网桥的ASN、国家等信息。

## 数据来源

MaxMind GeoLite2：https://github.com/P3TERX/GeoLite.mmdb/

Tor-Bridges-Collector：https://github.com/scriptzteam/Tor-Bridges-Collector

## 使用教程

1. 把这个Repo Clone到本地。
2. cd进项目目录
3. 创建虚拟环境: ```python3 -m venv myenv```
4. 激活虚拟环境: WIndows系统执行:```myenv\Scripts\activate``` Mac/Linux执行:```source myenv/bin/activate```
5. 安装依赖：```pip install -r requirements.txt```
6. Linux系统执行以下命令安装unrar ```sudo apt install unrar``` MacOS系统执行：```brew install carlocab/personal/unrar``` 如果没有安装unrar会造成解压错误
7. 在项目目录创建.env文件，按照你的需求修改：

```env
# 是否使用代理下载文件 (true/false)
USE_PROXY=true

# 代理URL (仅当USE_PROXY=true时生效)
# 支持HTTP和SOCKS代理
# 示例:
# HTTP代理: http://127.0.0.1:8080
# SOCKS5代理: socks5://127.0.0.1:1080
PROXY_URL=

# 并发处理线程数 (建议1-20)
MAX_WORKERS=15

# 其他可选配置
# HTTP请求超时时间(秒)
REQUEST_TIMEOUT=30

# 日志级别 (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO
```
8. 运行```python tor_bridge_analyzer.py```

## 仓库镜像

仓库的主要地址在GitHub：https://github.com/SexyOnion/tor_bridge_analyzer

考虑到中国政府对GitHub的限制，以及GitHub平台自身对文件大小的限制，本仓库在Gitea有镜像：https://gitea.com/Xijinping/tor_bridge_analyzer