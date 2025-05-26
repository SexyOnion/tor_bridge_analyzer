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

# Load environment variables
load_dotenv()

# Configure logging
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
        self.max_workers = int(os.getenv('MAX_WORKERS', '10'))  # Number of concurrent threads
        
        # MMDB file URLs
        self.mmdb_urls = {
            'asn': 'https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb',
            'country': 'https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb'
        }
        
        # Tor Bridges data URLs
        self.bridge_urls = {
            'obfs4': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-obfs4',
            'obfs4-ipv6': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-obfs4-ipv6',
            'snowflake-ipv4': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-snowflake-ipv4.rar',
            'snowflake-ipv6': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-snowflake-ipv6.rar',
            'vanilla': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-vanilla',
            'webtunnel': 'https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-webtunnel'
        }
        
        self.session = self._create_session()
        
        # Thread-local storage for MMDB readers
        self._local = threading.local()
        
    def _create_session(self):
        """Create HTTP session"""
        session = requests.Session()
        if self.use_proxy and self.proxy_url:
            session.proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            logger.info(f"Using proxy: {self.proxy_url}")
        return session
    
    def _find_mmdb_file(self, db_type):
        """Find MMDB file, supporting multiple naming formats"""
        possible_names = []
        
        if db_type == 'asn':
            possible_names = [
                'GeoLite2-ASN.mmdb',
                'GeoLite2-Asn.mmdb',
                'geolite2-asn.mmdb'
            ]
        elif db_type == 'country':
            possible_names = [
                'GeoLite2-COUNTRY.mmdb',  # All uppercase
                'GeoLite2-Country.mmdb',  # First letter uppercase
                'GeoLite2-country.mmdb',  # All lowercase
                'geolite2-country.mmdb'   # All lowercase with hyphen
            ]
        
        for name in possible_names:
            filepath = self.mmdb_dir / name
            if filepath.exists():
                logger.info(f"Found {db_type} database file: {filepath}")
                return filepath
        
        logger.warning(f"No {db_type} database file found, tried filenames: {possible_names}")
        return None
    
    def _get_mmdb_readers(self):
        """Get thread-local MMDB readers"""
        if not hasattr(self._local, 'asn_reader'):
            self._local.asn_reader = None
            self._local.country_reader = None
            
            # Find ASN database file
            asn_db_path = self._find_mmdb_file('asn')
            if asn_db_path:
                try:
                    self._local.asn_reader = geoip2.database.Reader(str(asn_db_path))
                    logger.debug(f"Successfully opened ASN database: {asn_db_path}")
                except Exception as e:
                    logger.error(f"Unable to open ASN database {asn_db_path}: {e}")
            
            # Find Country database file
            country_db_path = self._find_mmdb_file('country')
            if country_db_path:
                try:
                    self._local.country_reader = geoip2.database.Reader(str(country_db_path))
                    logger.debug(f"Successfully opened Country database: {country_db_path}")
                except Exception as e:
                    logger.error(f"Unable to open Country database {country_db_path}: {e}")
        
        return self._local.asn_reader, self._local.country_reader
    
    def create_directories(self):
        """Create necessary directories"""
        self.mmdb_dir.mkdir(exist_ok=True)
        self.bridges_dir.mkdir(exist_ok=True)
        logger.info("Created MMDB and Bridges directories")
    
    def download_file(self, url, filepath):
        """Download file"""
        try:
            logger.info(f"Downloading: {url}")
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            with open(filepath, 'wb') as f:
                f.write(response.content)
            logger.info(f"Download completed: {filepath}")
            return True
        except Exception as e:
            logger.error(f"Download failed {url}: {e}")
            return False
    
    def download_mmdb_files(self):
        """Download MMDB files"""
        for name, url in self.mmdb_urls.items():
            # Check if any format of the file already exists
            existing_file = self._find_mmdb_file(name)
            if existing_file:
                logger.info(f"MMDB file already exists: {existing_file}")
                continue
            
            # Use standard naming when downloading (first letter uppercase)
            if name == 'asn':
                filepath = self.mmdb_dir / "GeoLite2-ASN.mmdb"
            elif name == 'country':
                filepath = self.mmdb_dir / "GeoLite2-Country.mmdb"
            
            self.download_file(url, filepath)
    
    def download_bridge_files(self):
        """Download Tor Bridges files"""
        for name, url in self.bridge_urls.items():
            if name.endswith('.rar') or url.endswith('.rar'):
                filepath = self.bridges_dir / f"{name}.rar"
            else:
                filepath = self.bridges_dir / f"{name}.txt"
                
            if not filepath.exists():
                self.download_file(url, filepath)
            else:
                logger.info(f"Bridges file already exists: {filepath}")
    
    def extract_rar_files(self):
        """Extract RAR files"""
        for rar_file in self.bridges_dir.glob("*.rar"):
            try:
                logger.info(f"Extracting: {rar_file}")
                with rarfile.RarFile(rar_file) as rf:
                    rf.extractall(self.bridges_dir)
                logger.info(f"Extraction completed: {rar_file}")
            except Exception as e:
                logger.error(f"Extraction failed {rar_file}: {e}")
    
    @lru_cache(maxsize=1024)
    def parse_ip_from_bridge_line(self, line, bridge_type):
        """Parse IP address from bridge line (with cache)"""
        line = line.strip()
        if not line:
            return None
            
        try:
            if bridge_type in ['snowflake-ipv4', 'snowflake-ipv6']:
                # Snowflake format: direct IP address
                ip = line.strip()
                ipaddress.ip_address(ip)
                return ip
            elif bridge_type in ['obfs4', 'obfs4-ipv6']:
                # obfs4 format: obfs4 IP:PORT FINGERPRINT cert=... iat-mode=...
                parts = line.split(None, 2)  # Only split first 3 parts for performance
                if len(parts) >= 2:
                    ip_port = parts[1]
                    # Handle IPv6 format [::]:port
                    if ip_port.startswith('[') and ']:' in ip_port:
                        ip = ip_port.split(']:')[0][1:]
                    else:
                        ip = ip_port.split(':')[0]
                    ipaddress.ip_address(ip)
                    return ip
            elif bridge_type == 'vanilla':
                # vanilla format: IP:PORT FINGERPRINT
                parts = line.split(None, 1)  # Only split first space
                if len(parts) >= 1:
                    ip_port = parts[0]
                    ip = ip_port.split(':')[0]
                    ipaddress.ip_address(ip)
                    return ip
            elif bridge_type == 'webtunnel':
                # webtunnel format: webtunnel [IP]:PORT FINGERPRINT url=... ver=...
                parts = line.split(None, 3)  # Only split first 4 parts
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
        """Load bridge IPs from single file"""
        bridges = []
        try:
            with open(filepath, 'r', encoding='utf-8', buffering=8192) as f:
                for line in f:
                    line = line.strip()
                    if line:  # Skip empty lines
                        ip = self.parse_ip_from_bridge_line(line, bridge_type)
                        if ip:
                            bridges.append({
                                'ip': ip,
                                'type': bridge_type
                            })
        except Exception as e:
            logger.error(f"Failed to read file {filepath}: {e}")
        
        return bridges
    
    def load_bridge_ips(self):
        """Load all bridge IP addresses in parallel"""
        all_bridges = []
        
        # List of files to process
        file_tasks = []
        
        # Process text files
        for bridge_type in ['obfs4', 'obfs4-ipv6', 'vanilla', 'webtunnel']:
            filepath = self.bridges_dir / f"{bridge_type}.txt"
            if filepath.exists():
                file_tasks.append((filepath, bridge_type))
        
        # Process extracted snowflake files
        for bridge_type in ['snowflake-ipv4', 'snowflake-ipv6']:
            filepath = self.bridges_dir / f"bridges-{bridge_type}"
            if filepath.exists():
                file_tasks.append((filepath, bridge_type))
            else:
                logger.warning(f"Snowflake file does not exist: {filepath}")
        
        # Process files in parallel
        logger.info(f"Starting parallel loading of {len(file_tasks)} files...")
        with ThreadPoolExecutor(max_workers=min(len(file_tasks), 4)) as executor:
            future_to_file = {
                executor.submit(self.load_bridge_ips_from_file, filepath, bridge_type): (filepath, bridge_type)
                for filepath, bridge_type in file_tasks
            }
            
            with tqdm(total=len(file_tasks), desc="Loading files", unit="files") as pbar:
                for future in as_completed(future_to_file):
                    filepath, bridge_type = future_to_file[future]
                    try:
                        bridges = future.result()
                        all_bridges.extend(bridges)
                        logger.info(f"Loaded {len(bridges)} {bridge_type} bridges from {filepath}")
                    except Exception as e:
                        logger.error(f"Failed to process file {filepath}: {e}")
                    pbar.update(1)
        
        logger.info(f"Total loaded {len(all_bridges)} bridge IP addresses")
        
        # Count by type
        type_counts = {}
        for bridge in all_bridges:
            bridge_type = bridge['type']
            type_counts[bridge_type] = type_counts.get(bridge_type, 0) + 1
        
        for bridge_type, count in type_counts.items():
            logger.info(f"{bridge_type}: {count} bridges")
        
        return all_bridges
    
    def get_ip_info_batch(self, ip_batch):
        """Get IP information in batch"""
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
                # Get ASN information
                if asn_reader:
                    try:
                        response = asn_reader.asn(ip)
                        info['asn'] = response.autonomous_system_number
                        info['as_org'] = response.autonomous_system_organization
                    except geoip2.errors.AddressNotFoundError:
                        pass
            except Exception as e:
                logger.debug(f"Failed to get ASN info for {ip}: {e}")
            
            try:
                # Get country information
                if country_reader:
                    try:
                        response = country_reader.country(ip)
                        info['country'] = response.country.name
                        info['country_code'] = response.country.iso_code
                    except geoip2.errors.AddressNotFoundError:
                        pass
            except Exception as e:
                logger.debug(f"Failed to get country info for {ip}: {e}")
            
            results.append(info)
        
        return results
    
    def analyze_bridges(self):
        """Analyze all bridges in parallel"""
        bridges = self.load_bridge_ips()
        
        if not bridges:
            logger.warning("No bridge data found")
            return []
        
        logger.info("Starting bridge analysis...")
        
        # Check if MMDB files are available
        asn_file = self._find_mmdb_file('asn')
        country_file = self._find_mmdb_file('country')
        
        if not asn_file and not country_file:
            logger.error("No MMDB database files found!")
            return []
        
        if not asn_file:
            logger.warning("ASN database file not found, will skip ASN info lookup")
        
        if not country_file:
            logger.warning("Country database file not found, will skip country info lookup")
        
        # Create IP to type mapping
        ip_to_type = {bridge['ip']: bridge['type'] for bridge in bridges}
        unique_ips = list(ip_to_type.keys())
        
        # Batch processing, 100 IPs per batch
        batch_size = 100
        ip_batches = [unique_ips[i:i + batch_size] for i in range(0, len(unique_ips), batch_size)]
        
        analyzed_bridges = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_batch = {
                executor.submit(self.get_ip_info_batch, batch): batch
                for batch in ip_batches
            }
            
            with tqdm(total=len(unique_ips), desc="Analyzing bridges", unit="bridges") as pbar:
                for future in as_completed(future_to_batch):
                    try:
                        batch_results = future.result()
                        for result in batch_results:
                            # Add bridge type
                            result['bridge_type'] = ip_to_type[result['ip']]
                            analyzed_bridges.append(result)
                        pbar.update(len(batch_results))
                    except Exception as e:
                        logger.error(f"Batch processing failed: {e}")
                        pbar.update(len(future_to_batch[future]))
        
        logger.info(f"Completed analysis of {len(analyzed_bridges)} bridges")
        return analyzed_bridges
    
    def filter_china_bridges(self, bridges):
        """Filter bridges in China"""
        china_bridges = [
            bridge for bridge in bridges 
            if bridge['country_code'] == 'CN'
        ]
        logger.info(f"Found {len(china_bridges)} bridges in China")
        return china_bridges
    
    def filter_specific_orgs(self, bridges):
        """Filter bridges with specific organizations"""
        target_orgs = ['alibaba', 'tencent', 'huawei']
        specific_bridges = []
        
        for bridge in bridges:
            if bridge['as_org']:
                as_org_lower = bridge['as_org'].lower()
                if any(org in as_org_lower for org in target_orgs):
                    specific_bridges.append(bridge)
        
        logger.info(f"Found {len(specific_bridges)} bridges from specific organizations")
        return specific_bridges
    
    def save_json(self, data, filename):
        """Save data to JSON file"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"Saved {len(data)} records to {filename}")
    
    def cleanup_mmdb_readers(self):
        """Clean up MMDB readers"""
        if hasattr(self._local, 'asn_reader') and self._local.asn_reader:
            self._local.asn_reader.close()
        if hasattr(self._local, 'country_reader') and self._local.country_reader:
            self._local.country_reader.close()
    
    def run(self):
        """Run main program"""
        logger.info("Starting Tor Bridge Analyzer")
        
        try:
            # Create directories
            self.create_directories()
            
            # Download files
            logger.info("Downloading MMDB files...")
            self.download_mmdb_files()
            
            logger.info("Downloading Bridges files...")
            self.download_bridge_files()
            
            # Extract RAR files
            logger.info("Extracting RAR files...")
            self.extract_rar_files()
            
            # Analyze bridges
            all_bridges = self.analyze_bridges()
            
            if not all_bridges:
                logger.error("No bridge data analyzed")
                return
            
            # Filter data
            china_bridges = self.filter_china_bridges(all_bridges)
            specific_org_bridges = self.filter_specific_orgs(all_bridges)
            
            # Save results
            self.save_json(all_bridges, 'all_tor_bridges.json')
            self.save_json(china_bridges, 'china_tor_bridges.json')
            self.save_json(specific_org_bridges, 'specific_org_tor_bridges.json')
            
            logger.info("Analysis completed!")
            logger.info(f"Total bridges: {len(all_bridges)}")
            logger.info(f"China bridges: {len(china_bridges)}")
            logger.info(f"Specific org bridges: {len(specific_org_bridges)}")
            
        finally:
            # Clean up resources
            self.cleanup_mmdb_readers()

if __name__ == "__main__":
    analyzer = TorBridgeAnalyzer()
    analyzer.run()