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
import math

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Топовые источники (здесь сотни тысяч ключей)
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
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix.txt",
    "https://raw.githubusercontent.com/pawdroid/Free-servers/main/sub"
]

MAX_PROXIES = 500  # Выводим 500 лучших из 100 000+
OUTPUT_FILE = "best_ru_cidr_xhttp_reality.txt"
CONCURRENT_XRAY = 60 # 60 параллельных ядер Xray (чтобы не перегрузить GitHub Runner)
CONCURRENT_PING = 1000 # Параллельные TCP пинги (выдержит легко)

# Глобальные переменные для прогресс-бара
deep_test_total = 0
deep_test_done = 0

async def get_xray_binary():
    system = platform.system().lower()
    binary_name = "xray.exe" if system == "windows" else "xray"

    if os.path.exists(binary_name): return f"./{binary_name}" if system != "windows" else binary_name

    logger.info("Скачивание актуального Xray-core...")
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    if system == "windows":
        url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            with open("xray.zip", "wb") as f: f.write(await resp.read())
                
    with zipfile.ZipFile("xray.zip", 'r') as zip_ref: zip_ref.extractall(".")
    if system != "windows": os.chmod(binary_name, 0o755)
    return f"./{binary_name}" if system != "windows" else binary_name

def decode_base64_if_needed(content: str) -> str:
    content = content.strip()
    if not content: return ""
    if "://" in content[:50]: return content
    try:
        padded = content + "=" * ((4 - len(content) % 4) % 4)
        return base64.b64decode(padded).decode('utf-8', errors='ignore')
    except: return content

def is_valid_ip_or_cidr(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def parse_and_filter_vless_reality(link: str) -> dict:
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

        # Жестко требуем только Reality (обход ТСПУ 100%)
        if query.get('security', [''])[0].lower() != 'reality': return None
        
        # Только современные протоколы трафика
        transport = query.get('type', ['tcp'])[0].lower()
        if transport not in['tcp', 'grpc', 'ws', 'xhttp', 'splithttp']: return None
        
        # ОЧЕНЬ ВАЖНО: Только голые IP адреса. Если хост домен - DPI может заблочить DNS. IP-шники работают как лом!
        if not is_valid_ip_or_cidr(host): return None

        return {
            "link": link,
            "uuid": uuid,
            "host": host,
            "port": int(port),
            "type": transport,
            "security": "reality",
            "sni": query.get('sni', [''])[0],
            "pbk": query.get('pbk', [''])[0],
            "sid": query.get('sid', [''])[0],
            "fp": query.get('fp', ['chrome'])[0],
            "path": query.get('path', ['/'])[0],
            "host_http": query.get('host', [''])[0],
            "serviceName": query.get('serviceName', [''])[0],
            "mode": query.get('mode', ['multi'])[0],
            "tcp_ping": 9999.0,
            "latency": 9999.0,
            "speed_mbps": 0.0
        }
    except Exception: return None

async def fetch_source(session: aiohttp.ClientSession, url: str) -> list:
    try:
        async with session.get(url, timeout=15) as response:
            if response.status == 200:
                text = await response.text()
                return decode_base64_if_needed(text).split('\n')
    except: pass
    return[]

async def raw_tcp_ping(proxy: dict, semaphore: asyncio.Semaphore):
    """ФАЗА 1: Мгновенная проверка. Сканируем миллисекунды для тысяч узлов."""
    async with semaphore:
        start_time = time.monotonic()
        try:
            future = asyncio.open_connection(proxy["host"], proxy["port"])
            reader, writer = await asyncio.wait_for(future, timeout=3.0)
            proxy["tcp_ping"] = (time.monotonic() - start_time) * 1000
            writer.close()
            await writer.wait_closed()
        except:
            proxy["tcp_ping"] = 9999.0

async def test_proxy_with_xray(proxy: dict, port_queue: asyncio.Queue, xray_bin: str):
    """ФАЗА 2: Глубокая проверка в реальном ядре на обрыв трафика / EOF"""
    global deep_test_done, deep_test_total
    
    local_port = await port_queue.get()
    config_path = f"config_{local_port}.json"
    net_type = proxy['type']
    proc = None

    try:
        stream_settings = {
            "network": net_type,
            "security": "reality",
            "realitySettings": {
                "serverName": proxy['sni'], "publicKey": proxy['pbk'], 
                "shortId": proxy['sid'], "fingerprint": proxy['fp']
            }
        }

        # Блоки настроек для мультитестности
        if net_type in['xhttp', 'splithttp']:
            stream_settings[f"{net_type}Settings"] = {"path": urllib.parse.unquote(proxy['path'])}
            if proxy.get('host_http'): stream_settings[f"{net_type}Settings"]["host"] = proxy['host_http']
        elif net_type == 'grpc':
            stream_settings["grpcSettings"] = {
                "serviceName": urllib.parse.unquote(proxy['serviceName']),
                "multiMode": proxy['mode'] != 'gun'
            }
        elif net_type == 'ws':
            stream_settings["wsSettings"] = {
                "path": urllib.parse.unquote(proxy['path']),
                "headers": {"Host": proxy.get('host_http', proxy['sni'])}
            }
            
        config = {
            "log": {"loglevel": "none"},
            "inbounds":[{"port": local_port, "listen": "127.0.0.1", "protocol": "http"}],
            "outbounds":[{
                "protocol": "vless",
                "settings": {"vnext": [{"address": proxy['host'], "port": proxy['port'], 
                                        "users": [{"id": proxy['uuid'], "encryption": "none", "flow": ""}]}]},
                "streamSettings": stream_settings
            }]
        }

        with open(config_path, 'w', encoding='utf-8') as f: json.dump(config, f)

        proc = await asyncio.create_subprocess_exec(
            xray_bin, 'run', '-c', config_path,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.sleep(1.0) # Ожидание инициализации Xray
        
        proxy_url = f"http://127.0.0.1:{local_port}"
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # 1. URL test
            start = time.monotonic()
            async with session.get('http://cp.cloudflare.com/generate_204', proxy=proxy_url, timeout=5.0) as resp:
                if resp.status not in (200, 204): raise Exception("EOF/Bad Ping")
            proxy['latency'] = int((time.monotonic() - start) * 1000)
            
            # 2. Xray Speed/Download (качаем мегабайт - отбрасываем ложные узлы)
            start_down = time.monotonic()
            async with session.get('https://speed.cloudflare.com/__down?bytes=1500000', proxy=proxy_url, timeout=10.0) as resp:
                content = await resp.read()
                dl_time = time.monotonic() - start_down
                proxy['speed_mbps'] = round((len(content) * 8 / 1000000) / dl_time, 2)
                
    except Exception:
        proxy['latency'] = 9999.0
        proxy['speed_mbps'] = 0.0
    finally:
        if proc:
            try: proc.kill()
            except: pass
        if os.path.exists(config_path):
            try: os.remove(config_path)
            except: pass
        await port_queue.put(local_port)
        
        # Красивый логинг прогресса глубокого сканирования (чтобы лог не зависал)
        deep_test_done += 1
        if deep_test_done % 100 == 0 or deep_test_done == deep_test_total:
            logger.info(f"Прогресс глубокого Xray-теста: {deep_test_done} из {deep_test_total} узлов...")

async def main():
    global deep_test_total, deep_test_done
    
    logger.info("Запуск Абсолютного VPN-парсера. Никаких лимитов. МЯСОРУБКА АКТИВИРОВАНА.")
    xray_bin = await get_xray_binary()
    
    # 1. Сбор всех доступных прокси из интернета
    all_raw_lines = set()

    # Оптимизация aiohttp для парсинга тысяч ссылок (если их добавится больше)
    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks =[fetch_source(session, url) for url in SOURCES]
        results = await asyncio.gather(*tasks)
        for sublist in results:
            for line in sublist: all_raw_lines.add(line.strip())
                
    logger.info(f"Собрано сырых конфигов (Всего во всем интернете): {len(all_raw_lines)}")

    unique_map = {}
    for line in all_raw_lines:
        parsed = parse_and_filter_vless_reality(line)
        if parsed:
            # Дедупликация точная (IP:PORT)
            key = f"{parsed['host']}:{parsed['port']}"
            if key not in unique_map: unique_map[key] = parsed

    valid_proxies = list(unique_map.values())
    logger.info(f"Отфильтровано чистых IP с VLESS+Reality: {len(valid_proxies)} шт.")

    # ФАЗА 1: Массовый TCP-пинг. Пропускаем через него ВООБЩЕ ВСЕ IP-шники.
    if valid_proxies:
        logger.info(f"ФАЗА 1: Мгновенный TCP-сканер (пробиваем все {len(valid_proxies)} портов)...")
        sem = asyncio.Semaphore(CONCURRENT_PING)
        await asyncio.gather(*[raw_tcp_ping(p, sem) for p in valid_proxies])
        
        # Берем ВСЕ живые (никаких лимитов вроде top 300!)
        tcp_alive =[p for p in valid_proxies if p["tcp_ping"] < 9999.0]
        
        deep_test_total = len(tcp_alive)
        deep_test_done = 0
        
        logger.info(f"Доступны физически: {deep_test_total} серверов. Передаем их ВСЕХ на Xray ФАЗУ-2!")

        # ФАЗА 2: Глубокий тест ВСЕХ выживших узлов (100% обход EOF и блокировок РКН)
        if tcp_alive:
            port_queue = asyncio.Queue()
            for p in range(20000, 20000 + CONCURRENT_XRAY): port_queue.put_nowait(p)
                
            await asyncio.gather(*[test_proxy_with_xray(p, port_queue, xray_bin) for p in tcp_alive])

            # Вывод финальной элиты
            real_alive =[p for p in tcp_alive if p["latency"] < 9999.0]
            # Сортировка: сначала самые быстрые по пингу, при равенстве пинга - самые скоростные
            real_alive.sort(key=lambda x: (x["latency"], -x["speed_mbps"]))
            
            best_proxies = real_alive[:MAX_PROXIES]
            
            logger.info(f"АБСОЛЮТНО живых серверов после мясорубки: {len(real_alive)}.")
            logger.info(f"Сохраняем ТОП-{len(best_proxies)} самых скоростных в файл.")
            
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                for node in best_proxies:
                    base = node["link"].split('#')[0]
                    name_old = f"Proxy {node['host']}"
                    if '#' in node["link"]:
                        name_old = urllib.parse.unquote(node["link"].split('#', 1)[1])
                        name_old = re.sub(r'^\[.*?\]\s*', '', name_old)
                        
                    transport_icon = {"tcp": "TCP", "grpc": "gRPC", "ws": "WS", "xhttp": "XHTTP", "splithttp": "XHTTP"}.get(node['type'], node['type'])

                    # Прописываем метку скорости сразу в название профиля
                    # Пример: [142ms|19.5мб/c] TCP Reality | Старое Имя
                    new_name = urllib.parse.quote(f"[{node['latency']}ms|{node['speed_mbps']}мб/c] {transport_icon} Reality | {name_old}")
                    f.write(f"{base}#{new_name}\n")
                    
            logger.info(f"Успешно завершено! Файл {OUTPUT_FILE} готов.")
        else:
            logger.warning("Все сервера мертвы. Такое редко бывает.")
    else:
        logger.warning("Не найдено серверов на старте.")

if __name__ == "__main__":
    if platform.system() == "Windows": asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
