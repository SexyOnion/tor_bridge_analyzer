#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import logging
import requests
import geoip2.database
import geoip2.errors
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse
import rarfile
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import threading
from functools import lru_cache

# 加载环境变量
load_dotenv()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tor_bridge_analyzer.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TorBridgeAnalyzer:
    def __init__(self):
        self.mmdb_dir = Path("MMDB")
        self.bridges_dir = Path("Bridges")
        self.use_proxy = os.getenv('USE_PROXY', 'false').lower() == 'true'
        self.proxy_url = os.getenv('PROXY_URL', '')
        self.max_workers = int(os.getenv('MAX_WORKERS', '10'))  # 并发线程数
        
        # MMDB文件URLs
        self.mmdb_urls = {
            'asn': 'https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb',
            'country': 'https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb'
        }
        
        # Tor Bridges数据URLs
        self.bridge_urls = {
            'obfs4': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-obfs4',
            'obfs4-ipv6': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-obfs4-ipv6',
            'snowflake-ipv4': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-snowflake-ipv4.rar',
            'snowflake-ipv6': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-snowflake-ipv6.rar',
            'vanilla': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-vanilla',
            'webtunnel': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-webtunnel'
        }
        
        self.session = self._create_session()
        
        # 线程本地存储，用于MMDB reader
        self._local = threading.local()
        
    def _create_session(self):
        """创建HTTP会话"""
        session = requests.Session()
        if self.use_proxy and self.proxy_url:
            session.proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            logger.info(f"使用代理: {self.proxy_url}")
        return session
    
    def _get_mmdb_readers(self):
        """获取线程本地的MMDB readers"""
        if not hasattr(self._local, 'asn_reader'):
            asn_db_path = self.mmdb_dir / "GeoLite2-ASN.mmdb"
            country_db_path = self.mmdb_dir / "GeoLite2-Country.mmdb"
            
            self._local.asn_reader = None
            self._local.country_reader = None
            
            if asn_db_path.exists():
                try:
                    self._local.asn_reader = geoip2.database.Reader(str(asn_db_path))
                except Exception as e:
                    logger.error(f"无法打开ASN数据库: {e}")
            
            if country_db_path.exists():
                try:
                    self._local.country_reader = geoip2.database.Reader(str(country_db_path))
                except Exception as e:
                    logger.error(f"无法打开Country数据库: {e}")
        
        return self._local.asn_reader, self._local.country_reader
    
    def create_directories(self):
        """创建必要的目录"""
        self.mmdb_dir.mkdir(exist_ok=True)
        self.bridges_dir.mkdir(exist_ok=True)
        logger.info("已创建MMDB和Bridges目录")
    
    def download_file(self, url, filepath):
        """下载文件"""
        try:
            logger.info(f"正在下载: {url}")
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            with open(filepath, 'wb') as f:
                f.write(response.content)
            logger.info(f"下载完成: {filepath}")
            return True
        except Exception as e:
            logger.error(f"下载失败 {url}: {e}")
            return False
    
    def download_mmdb_files(self):
        """下载MMDB文件"""
        for name, url in self.mmdb_urls.items():
            filepath = self.mmdb_dir / f"GeoLite2-{name.upper()}.mmdb"
            if not filepath.exists():
                self.download_file(url, filepath)
            else:
                logger.info(f"MMDB文件已存在: {filepath}")
    
    def download_bridge_files(self):
        """下载Tor Bridges文件"""
        for name, url in self.bridge_urls.items():
            if name.endswith('.rar') or url.endswith('.rar'):
                filepath = self.bridges_dir / f"{name}.rar"
            else:
                filepath = self.bridges_dir / f"{name}.txt"
                
            if not filepath.exists():
                self.download_file(url, filepath)
            else:
                logger.info(f"Bridges文件已存在: {filepath}")
    
    def extract_rar_files(self):
        """解压RAR文件"""
        for rar_file in self.bridges_dir.glob("*.rar"):
            try:
                logger.info(f"正在解压: {rar_file}")
                with rarfile.RarFile(rar_file) as rf:
                    rf.extractall(self.bridges_dir)
                logger.info(f"解压完成: {rar_file}")
            except Exception as e:
                logger.error(f"解压失败 {rar_file}: {e}")
    
    @lru_cache(maxsize=1024)
    def parse_ip_from_bridge_line(self, line, bridge_type):
        """从网桥行中解析IP地址（带缓存）"""
        line = line.strip()
        if not line:
            return None
            
        try:
            if bridge_type in ['snowflake-ipv4', 'snowflake-ipv6']:
                # Snowflake格式：直接是IP地址
                ip = line.strip()
                ipaddress.ip_address(ip)
                return ip
            elif bridge_type in ['obfs4', 'obfs4-ipv6']:
                # obfs4格式：obfs4 IP:PORT FINGERPRINT cert=... iat-mode=...
                parts = line.split(None, 2)  # 只分割前3部分，提高性能
                if len(parts) >= 2:
                    ip_port = parts[1]
                    # 处理IPv6格式 [::]:port
                    if ip_port.startswith('[') and ']:' in ip_port:
                        ip = ip_port.split(']:')[0][1:]
                    else:
                        ip = ip_port.split(':')[0]
                    ipaddress.ip_address(ip)
                    return ip
            elif bridge_type == 'vanilla':
                # vanilla格式：IP:PORT FINGERPRINT
                parts = line.split(None, 1)  # 只分割第一个空格
                if len(parts) >= 1:
                    ip_port = parts[0]
                    ip = ip_port.split(':')[0]
                    ipaddress.ip_address(ip)
                    return ip
            elif bridge_type == 'webtunnel':
                # webtunnel格式：webtunnel [IP]:PORT FINGERPRINT url=... ver=...
                parts = line.split(None, 3)  # 只分割前4部分
                if len(parts) >= 2:
                    ip_port = parts[1]
                    if ip_port.startswith('[') and ']:' in ip_port:
                        ip = ip_port.split(']:')[0][1:]
                    else:
                        ip = ip_port.split(':')[0]
                    ipaddress.ip_address(ip)
                    return ip
        except (ValueError, IndexError):
            return None
        
        return None
    
    def load_bridge_ips_from_file(self, filepath, bridge_type):
        """从单个文件加载网桥IP"""
        bridges = []
        try:
            with open(filepath, 'r', encoding='utf-8', buffering=8192) as f:
                for line in f:
                    line = line.strip()
                    if line:  # 跳过空行
                        ip = self.parse_ip_from_bridge_line(line, bridge_type)
                        if ip:
                            bridges.append({
                                'ip': ip,
                                'type': bridge_type
                            })
        except Exception as e:
            logger.error(f"读取文件失败 {filepath}: {e}")
        
        return bridges
    
    def load_bridge_ips(self):
        """并行加载所有网桥IP地址"""
        all_bridges = []
        
        # 要处理的文件列表
        file_tasks = []
        
        # 处理文本文件
        for bridge_type in ['obfs4', 'obfs4-ipv6', 'vanilla', 'webtunnel']:
            filepath = self.bridges_dir / f"{bridge_type}.txt"
            if filepath.exists():
                file_tasks.append((filepath, bridge_type))
        
        # 处理解压后的snowflake文件
        for bridge_type in ['snowflake-ipv4', 'snowflake-ipv6']:
            filepath = self.bridges_dir / f"bridges-{bridge_type}"
            if filepath.exists():
                file_tasks.append((filepath, bridge_type))
            else:
                logger.warning(f"Snowflake文件不存在: {filepath}")
        
        # 并行处理文件
        logger.info(f"开始并行加载 {len(file_tasks)} 个文件...")
        with ThreadPoolExecutor(max_workers=min(len(file_tasks), 4)) as executor:
            future_to_file = {
                executor.submit(self.load_bridge_ips_from_file, filepath, bridge_type): (filepath, bridge_type)
                for filepath, bridge_type in file_tasks
            }
            
            with tqdm(total=len(file_tasks), desc="加载文件", unit="文件") as pbar:
                for future in as_completed(future_to_file):
                    filepath, bridge_type = future_to_file[future]
                    try:
                        bridges = future.result()
                        all_bridges.extend(bridges)
                        logger.info(f"从 {filepath} 加载了 {len(bridges)} 个 {bridge_type} 网桥")
                    except Exception as e:
                        logger.error(f"处理文件失败 {filepath}: {e}")
                    pbar.update(1)
        
        logger.info(f"总共加载了 {len(all_bridges)} 个网桥IP地址")
        
        # 按类型统计
        type_counts = {}
        for bridge in all_bridges:
            bridge_type = bridge['type']
            type_counts[bridge_type] = type_counts.get(bridge_type, 0) + 1
        
        for bridge_type, count in type_counts.items():
            logger.info(f"{bridge_type}: {count} 个网桥")
        
        return all_bridges
    
    def get_ip_info_batch(self, ip_batch):
        """批量获取IP信息"""
        results = []
        asn_reader, country_reader = self._get_mmdb_readers()
        
        for ip in ip_batch:
            info = {
                'ip': ip,
                'asn': None,
                'as_org': None,
                'country': None,
                'country_code': None
            }
            
            try:
                # 获取ASN信息
                if asn_reader:
                    try:
                        response = asn_reader.asn(ip)
                        info['asn'] = response.autonomous_system_number
                        info['as_org'] = response.autonomous_system_organization
                    except geoip2.errors.AddressNotFoundError:
                        pass
            except Exception as e:
                logger.debug(f"获取ASN信息失败 {ip}: {e}")
            
            try:
                # 获取国家信息
                if country_reader:
                    try:
                        response = country_reader.country(ip)
                        info['country'] = response.country.name
                        info['country_code'] = response.country.iso_code
                    except geoip2.errors.AddressNotFoundError:
                        pass
            except Exception as e:
                logger.debug(f"获取国家信息失败 {ip}: {e}")
            
            results.append(info)
        
        return results
    
    def analyze_bridges(self):
        """并行分析所有网桥"""
        bridges = self.load_bridge_ips()
        
        if not bridges:
            logger.warning("没有找到网桥数据")
            return []
        
        logger.info("开始分析网桥信息...")
        
        # 创建IP到类型的映射
        ip_to_type = {bridge['ip']: bridge['type'] for bridge in bridges}
        unique_ips = list(ip_to_type.keys())
        
        # 批量处理，每批处理100个IP
        batch_size = 100
        ip_batches = [unique_ips[i:i + batch_size] for i in range(0, len(unique_ips), batch_size)]
        
        analyzed_bridges = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_batch = {
                executor.submit(self.get_ip_info_batch, batch): batch
                for batch in ip_batches
            }
            
            with tqdm(total=len(unique_ips), desc="分析网桥", unit="个") as pbar:
                for future in as_completed(future_to_batch):
                    try:
                        batch_results = future.result()
                        for result in batch_results:
                            # 添加网桥类型
                            result['bridge_type'] = ip_to_type[result['ip']]
                            analyzed_bridges.append(result)
                        pbar.update(len(batch_results))
                    except Exception as e:
                        logger.error(f"批量处理失败: {e}")
                        pbar.update(len(future_to_batch[future]))
        
        logger.info(f"完成分析 {len(analyzed_bridges)} 个网桥")
        return analyzed_bridges
    
    def filter_china_bridges(self, bridges):
        """筛选中国的网桥"""
        china_bridges = [
            bridge for bridge in bridges 
            if bridge['country_code'] == 'CN'
        ]
        logger.info(f"找到 {len(china_bridges)} 个中国网桥")
        return china_bridges
    
    def filter_specific_orgs(self, bridges):
        """筛选包含特定组织的网桥"""
        target_orgs = ['alibaba', 'tencent', 'huawei']
        specific_bridges = []
        
        for bridge in bridges:
            if bridge['as_org']:
                as_org_lower = bridge['as_org'].lower()
                if any(org in as_org_lower for org in target_orgs):
                    specific_bridges.append(bridge)
        
        logger.info(f"找到 {len(specific_bridges)} 个特定组织网桥")
        return specific_bridges
    
    def save_json(self, data, filename):
        """保存数据为JSON文件"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"已保存 {len(data)} 条记录到 {filename}")
    
    def cleanup_mmdb_readers(self):
        """清理MMDB readers"""
        if hasattr(self._local, 'asn_reader') and self._local.asn_reader:
            self._local.asn_reader.close()
        if hasattr(self._local, 'country_reader') and self._local.country_reader:
            self._local.country_reader.close()
    
    def run(self):
        """运行主程序"""
        logger.info("开始运行Tor网桥分析器")
        
        try:
            # 创建目录
            self.create_directories()
            
            # 下载文件
            logger.info("下载MMDB文件...")
            self.download_mmdb_files()
            
            logger.info("下载Bridges文件...")
            self.download_bridge_files()
            
            # 解压RAR文件
            logger.info("解压RAR文件...")
            self.extract_rar_files()
            
            # 分析网桥
            all_bridges = self.analyze_bridges()
            
            if not all_bridges:
                logger.error("没有分析到任何网桥数据")
                return
            
            # 筛选数据
            china_bridges = self.filter_china_bridges(all_bridges)
            specific_org_bridges = self.filter_specific_orgs(all_bridges)
            
            # 保存结果
            self.save_json(all_bridges, 'all_tor_bridges.json')
            self.save_json(china_bridges, 'china_tor_bridges.json')
            self.save_json(specific_org_bridges, 'specific_org_tor_bridges.json')
            
            logger.info("分析完成！")
            logger.info(f"总网桥数: {len(all_bridges)}")
            logger.info(f"中国网桥数: {len(china_bridges)}")
            logger.info(f"特定组织网桥数: {len(specific_org_bridges)}")
            
        finally:
            # 清理资源
            self.cleanup_mmdb_readers()

if __name__ == "__main__":
    analyzer = TorBridgeAnalyzer()
    analyzer.run()