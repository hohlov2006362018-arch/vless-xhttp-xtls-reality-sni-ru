import asyncio
import aiohttp
import base64
import urllib.parse
import time
import re
import ipaddress
import logging
import platform
import os
import zipfile
import json

# Настройка красивого вывода
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Источники
SOURCES =[
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/AllConfigsSub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://github.com/Epodonios/v2ray-configs/raw/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/config.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS#STR.BYPASS",
    "https://raw.githubusercontent.com/Delta-Kronecker/Xray/refs/heads/main/data/working_url/working_all_urls.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/refs/heads/master/result/nodes",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix.txt",
    "https://raw.githubusercontent.com/pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/tbbatbb/Proxy/master/dist/v2ray.config.txt",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless.txt"
]

MAX_PROXIES = 250
OUTPUT_FILE = "best_ru_cidr_xhttp_reality.txt"
CONCURRENT_TESTS = 30 # Количество одновременно тестируемых серверов

async def get_xray_binary():
    """Скачивает Xray-core для полноценной симуляции клиента прямо в парсере."""
    system = platform.system().lower()
    binary_name = "xray.exe" if system == "windows" else "xray"

    if os.path.exists(binary_name):
        return f"./{binary_name}" if system != "windows" else binary_name

    logger.info("Скачивание актуального Xray-core для глубокого тестирования скорости и трафика...")
    
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    if system == "windows":
        url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            with open("xray.zip", "wb") as f:
                f.write(await resp.read())
                
    with zipfile.ZipFile("xray.zip", 'r') as zip_ref:
        zip_ref.extractall(".")
        
    if system != "windows":
        os.chmod(binary_name, 0o755)
        
    return f"./{binary_name}" if system != "windows" else binary_name

def decode_base64_if_needed(content: str) -> str:
    content = content.strip()
    if not content: return ""
    if "://" in content[:50]: return content
    try:
        padded = content + "=" * ((4 - len(content) % 4) % 4)
        return base64.b64decode(padded).decode('utf-8', errors='ignore')
    except Exception:
        return content

def is_valid_ip_or_cidr(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def parse_and_filter_vless(link: str) -> dict:
    link = link.strip()
    if not link.startswith("vless://"): return None
    
    base_link = link.split('#')[0]
    try:
        parsed = urllib.parse.urlsplit(base_link)
        query = urllib.parse.parse_qs(parsed.query)
        uuid_host = parsed.netloc
        if '@' not in uuid_host: return None
        
        uuid, host_port = uuid_host.split('@', 1)
        host, port = host_port.rsplit(':', 1)

        if query.get('security', [''])[0].lower() != 'reality': return None
        transport = query.get('type', [''])[0].lower()
        if transport not in ['xhttp', 'splithttp']: return None
        
        sni = query.get('sni', [''])[0].lower()
        if not (sni.endswith('.ru') or '.ru' in sni): return None
        if not is_valid_ip_or_cidr(host): return None

        return {
            "link": link,
            "uuid": uuid,
            "host": host,
            "port": int(port),
            "type": transport,
            "security": "reality",    # Добавлен недостающий ключ безопасности
            "sni": sni,
            "pbk": query.get('pbk', [''])[0],
            "sid": query.get('sid', [''])[0],
            "fp": query.get('fp', ['chrome'])[0],
            "path": query.get('path', ['/'])[0],
            "host_http": query.get('host', [''])[0],
            "latency": 9999.0,
            "speed_mbps": 0.0
        }
    except Exception:
        return None

async def fetch_source(session: aiohttp.ClientSession, url: str) -> list:
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                text = await response.text()
                return decode_base64_if_needed(text).split('\n')
    except Exception:
        pass
    return[]

async def test_proxy_with_xray(proxy: dict, port_queue: asyncio.Queue, xray_bin: str):
    """Глубокий тест прокси: запуск локального ядра, тест TTFB, скачивание 1МБ (Имитация Speedtest)"""
    local_port = await port_queue.get()
    config_path = f"config_{local_port}.json"
    net_type = proxy['type'] # xhttp или splithttp
    proc = None
    success = False

    try:
        # Формируем чистый конфиг для Xray
        config = {
            "log": {"loglevel": "none"},
            "inbounds":[{"port": local_port, "listen": "127.0.0.1", "protocol": "http"}],
            "outbounds":[{
                "protocol": "vless",
                "settings": {"vnext": [{"address": proxy['host'], "port": proxy['port'], 
                                        "users": [{"id": proxy['uuid'], "encryption": "none", "flow": ""}]}]},
                "streamSettings": {
                    "network": net_type,
                    "security": proxy['security'],
                    "realitySettings": {"serverName": proxy['sni'], "publicKey": proxy['pbk'], 
                                        "shortId": proxy['sid'], "fingerprint": proxy['fp']},
                }
            }]
        }
        
        # Динамически подставляем настройки транспорта для обратной совместимости xhttp/splithttp
        settings_key = f"{net_type}Settings"
        config["outbounds"][0]["streamSettings"][settings_key] = {"path": urllib.parse.unquote(proxy['path'])}
        if proxy.get('host_http'):
            config["outbounds"][0]["streamSettings"][settings_key]["host"] = proxy['host_http']

        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f)

        # Запускаем изолированный туннель
        proc = await asyncio.create_subprocess_exec(
            xray_bin, 'run', '-c', config_path,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.sleep(1.0) # Даем ядру время запустить http-inbound порт
        
        proxy_url = f"http://127.0.0.1:{local_port}"
        
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # ТЕСТ 1: URL Test (Пинг / TTFB) через генератор 204
            start = time.monotonic()
            async with session.get('http://cp.cloudflare.com/generate_204', proxy=proxy_url, timeout=4.0) as resp:
                if resp.status not in (200, 204): raise Exception("Bad Ping")
            
            latency = int((time.monotonic() - start) * 1000)
            
            # ТЕСТ 2: Speed / Download (Качаем 1 мегабайт для проверки обрыва трафика(EOF))
            start_down = time.monotonic()
            async with session.get('https://speed.cloudflare.com/__down?bytes=1000000', proxy=proxy_url, timeout=8.0) as resp:
                content = await resp.read()
                dl_time = time.monotonic() - start_down
                speed_mbps = (len(content) * 8 / 1000000) / dl_time
                
            proxy['latency'] = latency
            proxy['speed_mbps'] = round(speed_mbps, 2)
            success = True
            
    except Exception:
        proxy['latency'] = 9999.0
        proxy['speed_mbps'] = 0.0
    finally:
        # Убиваем процесс жёстко и убираем следы
        if proc:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            
        if os.path.exists(config_path):
            try:
                os.remove(config_path)
            except OSError:
                pass
                
        await port_queue.put(local_port) # Освобождаем порт для следующего
        
    return success

async def main():
    logger.info("Запуск умного VPN-парсера...")
    xray_bin = await get_xray_binary()
    
    all_raw_lines = set()
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_source(session, url) for url in SOURCES]
        results = await asyncio.gather(*tasks)
        for sublist in results:
            for line in sublist:
                all_raw_lines.add(line.strip())
                
    logger.info(f"Собрано сырых узлов: {len(all_raw_lines)}")

    unique_proxies_map = {}
    for line in all_raw_lines:
        parsed = parse_and_filter_vless(line)
        if parsed is not None:
            if parsed['host'] not in unique_proxies_map:
                unique_proxies_map[parsed['host']] = parsed

    valid_proxies = list(unique_proxies_map.values())
    logger.info(f"Прошли базовую фильтрацию (Уникальные VLESS+XHTTP+Reality+RU): {len(valid_proxies)} шт.")

    if valid_proxies:
        logger.info("Запуск ГЛУБОКОГО теста. URL Test -> Соединение TLS -> Download Speed Test (1MB)...")
        
        port_queue = asyncio.Queue()
        for p in range(20000, 20000 + CONCURRENT_TESTS):
            port_queue.put_nowait(p)
            
        tasks =[test_proxy_with_xray(p, port_queue, xray_bin) for p in valid_proxies]
        await asyncio.gather(*tasks)

        alive_proxies = [p for p in valid_proxies if p["latency"] < 9999.0]
        alive_proxies.sort(key=lambda x: (x["latency"], -x["speed_mbps"]))
        best_proxies = alive_proxies[:MAX_PROXIES]
        
        logger.info(f"Тест завершен. Отсеяно МЁРТВЫХ(EOF): {len(valid_proxies)-len(alive_proxies)} шт.")
        logger.info(f"АБСОЛЮТНО ЖИВЫХ узлов: {len(alive_proxies)}. Сохранено лучших: {len(best_proxies)}.")
        
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for node in best_proxies:
                link = node["link"]
                if '#' in link:
                    base, name = link.rsplit('#', 1)
                    name = urllib.parse.unquote(name)
                    name = re.sub(r'^\[.*?\]\s*', '', name)
                else:
                    base = link; name = "Proxy"
                
                new_name = urllib.parse.quote(f"[{node['latency']}ms|{node['speed_mbps']}Mbps] {name}")
                new_link = f"{base}#{new_name}"
                
                f.write(new_link + "\n")
                
        logger.info(f"Файл отлично сохранен: {OUTPUT_FILE}")
    else:
        logger.warning("Не найдено узлов до старта Speedtest.")

if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
