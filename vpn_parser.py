import requests
import re
import urllib.parse
import time
import random
import os
import socket
import maxminddb
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- НАСТРОЙКИ ПАРСЕРА ---

# --- ТОЛЬКО CIDR ДЛЯ SNI ---
RUSSIAN_CIDRS_RAW = """
2.63.0.0/17
2.63.128.0/18
2.63.192.0/19
2.63.224.0/21
2.63.232.0/23
2.63.235.0/24
"""

# Агрегаторы конфигов
GITHUB_SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vless",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless"
]

GEOIP_DB_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"

class VlessParser:
    def __init__(self):
        self.session = requests.Session()
        self.ensure_geoip_db()
        self.geo_reader = maxminddb.open_database(GEOIP_DB_PATH)
        self.ping_cache = {}
        self.cidrs = [x.strip() for x in RUSSIAN_CIDRS_RAW.strip().split('\n') if x.strip() and not x.startswith('#')]

    def ensure_geoip_db(self):
        if not os.path.exists(GEOIP_DB_PATH):
            res = requests.get(GEOIP_DB_URL, stream=True)
            with open(GEOIP_DB_PATH, 'wb') as f:
                for chunk in res.iter_content(chunk_size=8192):
                    f.write(chunk)

    def is_alive(self, host, port, timeout=1.5):
        cache_key = f"{host}:{port}"
        if cache_key in self.ping_cache: return self.ping_cache[cache_key]
        try:
            with socket.create_connection((host, port), timeout=timeout):
                self.ping_cache[cache_key] = True
                return True
        except:
            self.ping_cache[cache_key] = False
            return False

    def get_ip_country(self, host):
        try:
            ip = host
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                ip = socket.gethostbyname(host)
            geo_info = self.geo_reader.get(ip)
            return geo_info['country']['iso_code'] if geo_info else "UN"
        except: return "UN"

    def get_random_ip_from_cidr(self):
        try:
            cidr_str = random.choice(self.cidrs)
            network = ipaddress.IPv4Network(cidr_str, strict=False)
            min_ip, max_ip = int(network.network_address) + 1, int(network.broadcast_address) - 1
            return str(ipaddress.IPv4Address(random.randint(min_ip, max_ip)))
        except: return "1.1.1.1"

    def parse_and_filter(self, uri):
        if not uri.startswith("vless://"): return None
        try:
            main_part, name = uri.split('#', 1) if '#' in uri else (uri, "VPN")
            main_part = main_part[8:]
            credentials, query = main_part.split('?', 1)
            uuid, host_port = credentials.split('@', 1)
            host, port = host_port.rsplit(':', 1)
            params = dict(urllib.parse.parse_qsl(query))
            
            if params.get("security") != "reality": return None
            if not self.is_alive(host, int(port)): return None
            
            country = self.get_ip_country(host)
            sni = self.get_random_ip_from_cidr()
            params["sni"] = sni
            
            new_query = urllib.parse.urlencode(params)
            return f"vless://{uuid}@{host}:{port}?{new_query}#{urllib.parse.quote(f'[{country}] CIDR_SNI:{sni}')}"
        except: return None

    def run(self):
        print("[*] Сбор ключей...")
        links = set()
        for url in GITHUB_SOURCES:
            try:
                res = self.session.get(url, timeout=10)
                links.update(re.findall(r'vless://[^\s<>"\']+', res.text))
            except: pass
        
        print(f"[*] Проверка {len(links)} серверов...")
        valid = []
        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = [ex.submit(self.parse_and_filter, l) for l in links]
            for f in as_completed(futures):
                res = f.result()
                if res: valid.append(res)
        
        # СОХРАНЕНИЕ: Убираем /content/ для работы в GitHub Actions
        with open("best_ru_sni_reality.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(valid))
        print(f"[+] Готово! Сохранено: {len(valid)}")

if __name__ == "__main__":
    VlessParser().run()