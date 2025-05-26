# Tor Bridge Analysis Script

[中文](https://github.com/SexyOnion/tor_bridge_analyzer/blob/main/README_CN.md)

## About

This project originated from a discussion in the Yangzhi community, where I first conceived this script in the post ["Looking for Tor Bridges Operated by the CCP"](https://yangzhi.org/question/6783/).

After writing this script, I discovered a staggering number of Tor bridges from China - specifically 26,483 Chinese bridges. These bridges are almost certainly honeypot bridges set up by the CCP. The relevant data is in the example directory of this project, with all files in JSON format.

## Features

This project contains a Python script that, when run, will download the latest version of the GeoLite database and the most recently obtained Tor bridge list. The script will then parse the ASN, country, and other information of Tor bridges through the GeoLite database.

## Data Sources

MaxMind GeoLite2: https://github.com/P3TERX/GeoLite.mmdb/

Tor-Bridges-Collector: https://github.com/scriptzteam/Tor-Bridges-Collector

## Usage Tutorial

1. Clone this repo to your local machine.
2. cd into the project directory
3. Create a virtual environment: ```python3 -m venv myenv```
4. Activate the virtual environment: Windows: ```myenv\Scripts\activate``` Mac/Linux: ```source myenv/bin/activate```
5. Install dependencies: ```pip install -r requirements.txt```
6. For Linux systems, install unrar with: ```sudo apt install unrar``` For macOS: ```brew install carlocab/personal/unrar``` Not installing unrar will cause extraction errors
7. Create a .env file in the project directory and modify according to your needs:

```env
# Whether to use proxy for downloading files (true/false)
USE_PROXY=false

# Proxy URL (only effective when USE_PROXY=true)
# Supports HTTP and SOCKS proxy
# Examples:
# HTTP proxy: http://127.0.0.1:8080
# SOCKS5 proxy: socks5://127.0.0.1:1080
PROXY_URL=

# Number of concurrent processing threads (recommended 1-20)
MAX_WORKERS=15

# Other optional configurations
# HTTP request timeout in seconds
REQUEST_TIMEOUT=30

# Log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO
```
8. Run ```python tor_bridge_analyzer.py```

## Repository Mirrors

The primary repository address is on GitHub: https://github.com/SexyOnion/tor_bridge_analyzer

Considering the Chinese government's restrictions on GitHub and GitHub's own file size limitations, this repository has a mirror on Gitea: https://gitea.com/Xijinping/tor_bridge_analyzer