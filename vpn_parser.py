import asyncio
import aiohttp
import base64
import urllib.parse
import time
import re
import os
import zipfile
import json
import platform
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Топовые источники (Сотни тысяч ключей)
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

OUTPUT_FILE = "best_ru_cidr_xhttp_reality.txt" # Оставили имя чтобы не менять YML в Actions
CONCURRENT_XRAY = 80    # 80 ядер Xray одновременно
CONCURRENT_PING = 1500  # 1500 потоков пинга

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

def b64_decode(text: str) -> str:
    try:
        padded = text + "=" * ((4 - len(text) % 4) % 4)
        return base64.b64decode(padded).decode('utf-8', errors='ignore')
    except: return text

def universal_proxy_parser(link: str) -> dict:
    """Парсит АБСОЛЮТНО ЛЮБЫЕ ссылки (VLESS, VMESS, TROJAN, SS) и готовит их Xray-json конфиги"""
    link = link.strip()
    if not link: return None
    
    try:
        # ---- VMESS ----
        if link.startswith("vmess://"):
            data = json.loads(b64_decode(link[8:]))
            host = data.get("add")
            port = int(data.get("port"))
            outbound = {
                "protocol": "vmess",
                "settings": {"vnext":[{"address": host, "port": port, "users":[{"id": data.get("id"), "alterId": int(data.get("aid", 0))}]}]},
                "streamSettings": {"network": data.get("net", "tcp"), "security": data.get("tls", "none")}
            }
            net = data.get("net", "tcp")
            if net == "ws": outbound["streamSettings"]["wsSettings"] = {"path": data.get("path", "/"), "headers": {"Host": data.get("host", "")}}
            elif net == "grpc": outbound["streamSettings"]["grpcSettings"] = {"serviceName": data.get("path", "")}
            if data.get("sni"): outbound["streamSettings"]["tlsSettings"] = {"serverName": data.get("sni")}
            
            return {"link": link, "host": host, "port": port, "proto": "VMess", "type": net, "xray_outbound": outbound, "name": data.get("ps", "VMess"), "tcp_ping": 9999.0, "latency": 9999.0, "speed_mbps": 0.0}

        # ---- VLESS & TROJAN ----
        elif link.startswith("vless://") or link.startswith("trojan://"):
            proto = link.split("://")[0]
            base, query = (link.split("?", 1) + [""])[:2]
            base, name = (base.split("#", 1) + [""])[:2]
            auth, host_port = base.split("://")[1].split("@", 1)
            host, port = host_port.rsplit(":", 1)
            port = int(port)
            q = dict(urllib.parse.parse_qsl(query))
            
            outbound = {"protocol": proto, "settings": {}, "streamSettings": {"network": q.get("type", "tcp"), "security": q.get("security", "none")}}
            if proto == "vless": outbound["settings"]["vnext"] =[{"address": host, "port": port, "users": [{"id": auth, "encryption": q.get("encryption", "none")}]}]
            else: outbound["settings"]["servers"] =[{"address": host, "port": port, "password": auth}]
                
            net = q.get("type", "tcp")
            if net == "ws": outbound["streamSettings"]["wsSettings"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", q.get("sni", ""))}}
            elif net in["xhttp", "splithttp"]: outbound["streamSettings"][f"{net}Settings"] = {"path": q.get("path", "/"), "host": q.get("host", "")}
            elif net == "grpc": outbound["streamSettings"]["grpcSettings"] = {"serviceName": q.get("serviceName", ""), "multiMode": q.get("mode", "multi") != "gun"}
            
            if q.get("security") == "reality":
                outbound["streamSettings"]["realitySettings"] = {"serverName": q.get("sni", ""), "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""), "fingerprint": q.get("fp", "chrome")}
            elif q.get("security") == "tls":
                outbound["streamSettings"]["tlsSettings"] = {"serverName": q.get("sni", ""), "fingerprint": q.get("fp", "chrome")}
                
            return {"link": link, "host": host, "port": port, "proto": proto.capitalize(), "type": net, "xray_outbound": outbound, "name": urllib.parse.unquote(name), "tcp_ping": 9999.0, "latency": 9999.0, "speed_mbps": 0.0}

        # ---- SHADOWSOCKS ----
        elif link.startswith("ss://"):
            base, name = (link.split("#", 1) + [""])[:2]
            base = base[5:]
            if "@" in base:
                b64, host_port = base.split("@", 1)
                host, port = host_port.rsplit(":", 1)
                method, password = b64_decode(b64).split(":", 1)
            else:
                method_pass, host_port = b64_decode(base).split("@", 1)
                method, password = method_pass.split(":", 1)
                host, port = host_port.rsplit(":", 1)
                
            outbound = {"protocol": "shadowsocks", "settings": {"servers":[{"address": host, "port": int(port), "method": method, "password": password}]}}
            return {"link": link, "host": host, "port": int(port), "proto": "ShadowSocks", "type": "tcp", "xray_outbound": outbound, "name": urllib.parse.unquote(name), "tcp_ping": 9999.0, "latency": 9999.0, "speed_mbps": 0.0}

    except Exception: return None
    return None

async def fetch_source(session: aiohttp.ClientSession, url: str) -> list:
    try:
        async with session.get(url, timeout=12) as response:
            if response.status == 200:
                text = await response.text()
                # Пытаемся раскодировать если это Base64 список
                if not "://" in text[:50]: text = b64_decode(text)
                return text.split('\n')
    except: pass
    return[]

async def raw_tcp_ping(proxy: dict, semaphore: asyncio.Semaphore):
    """ФАЗА 1: Мгновенный отсев 90% нерабочего шлака через TCP Socket"""
    async with semaphore:
        start_time = time.monotonic()
        try:
            future = asyncio.open_connection(proxy["host"], proxy["port"])
            reader, writer = await asyncio.wait_for(future, timeout=2.5) # Жесткий таймаут 2.5 сек
            proxy["tcp_ping"] = (time.monotonic() - start_time) * 1000
            writer.close()
            await writer.wait_closed()
        except: pass

async def test_proxy_with_xray(proxy: dict, port_queue: asyncio.Queue, xray_bin: str):
    """ФАЗА 2: Глубокий URL и Speed тест через ядро Xray - ТОЛЬКО ХАРДКОР"""
    global deep_test_done, deep_test_total
    
    local_port = await port_queue.get()
    config_path = f"config_{local_port}.json"
    proc = None

    try:
        config = {
            "log": {"loglevel": "none"},
            "inbounds":[{"port": local_port, "listen": "127.0.0.1", "protocol": "http"}],
            "outbounds":[proxy["xray_outbound"]]
        }
        with open(config_path, 'w', encoding='utf-8') as f: json.dump(config, f)

        proc = await asyncio.create_subprocess_exec(
            xray_bin, 'run', '-c', config_path,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.sleep(1.0) # Ожидание поднятия порта
        
        proxy_url = f"http://127.0.0.1:{local_port}"
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # ТЕСТ 1: ЖИВОЙ ЛИ ТРАФИК? (URL TEST)
            start = time.monotonic()
            async with session.get('http://cp.cloudflare.com/generate_204', proxy=proxy_url, timeout=5.0) as resp:
                if resp.status not in (200, 204): raise Exception("EOF/Bad Ping")
            proxy['latency'] = int((time.monotonic() - start) * 1000)
            
            # ТЕСТ 2: КАЧАЕМ 500КБ ФАЙЛ С CLOUDFLARE (ОТСЕКАЕМ БЛОКИРОВКИ)
            start_down = time.monotonic()
            async with session.get('https://speed.cloudflare.com/__down?bytes=500000', proxy=proxy_url, timeout=7.0) as resp:
                content = await resp.read()
                dl_time = time.monotonic() - start_down
                proxy['speed_mbps'] = round((len(content) * 8 / 1000000) / dl_time, 2)
                
    except Exception: pass
    finally:
        if proc:
            try: proc.kill()
            except: pass
        if os.path.exists(config_path):
            try: os.remove(config_path)
            except: pass
        await port_queue.put(local_port)
        
        # Логируем каждые 50 проверенных узлов чтобы видеть прогресс!
        deep_test_done += 1
        if deep_test_done % 50 == 0 or deep_test_done == deep_test_total:
            logger.info(f"⚡ Глубокая Xray Проверка: {deep_test_done} из {deep_test_total} серверов пройдена...")

async def main():
    global deep_test_total, deep_test_done
    logger.info("🔥 ЗАПУСК АБСОЛЮТНОГО ПАРСЕРА БЕЗ ЛИМИТОВ 🔥")
    xray_bin = await get_xray_binary()
    
    # 1. Скачиваем весь интернет (все подписки)
    all_raw_lines = set()
    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks =[fetch_source(session, url) for url in SOURCES]
        results = await asyncio.gather(*tasks)
        for sublist in results:
            for line in sublist: all_raw_lines.add(line.strip())
                
    logger.info(f"Собрано сырых ссылок из всех источников: {len(all_raw_lines)}")

    unique_map = {}
    for line in all_raw_lines:
        parsed = universal_proxy_parser(line)
        if parsed:
            # Дедупликация (не проверяем одни и те же сервера дважды)
            key = f"{parsed['host']}:{parsed['port']}"
            if key not in unique_map: unique_map[key] = parsed

    valid_proxies = list(unique_map.values())
    logger.info(f"Успешно конвертировано в Xray Json: {len(valid_proxies)} уникальных серверов (VLESS/VMESS/Trojan/SS).")

    # ФАЗА 1: Массовый TCP Пинг всех 10-100К серверов!
    if valid_proxies:
        logger.info(f"ФАЗА 1: Мгновенная TCP-Атака (Ищем живые порты средь {len(valid_proxies)} узлов)...")
        sem = asyncio.Semaphore(CONCURRENT_PING)
        await asyncio.gather(*[raw_tcp_ping(p, sem) for p in valid_proxies])
        
        # БЕРЕМ ВСЕ ЖИВЫЕ (Никаких лимитов)
        tcp_alive =[p for p in valid_proxies if p["tcp_ping"] < 9999.0]
        deep_test_total = len(tcp_alive)
        deep_test_done = 0
        
        logger.info(f"✅ Физически в сети: {deep_test_total} серверов. НАЧИНАЮ XRAY SPEEDTEST ДЛЯ КАЖДОГО ИЗ НИХ!")

        # ФАЗА 2: Прогоняем ВЕСЬ живой список через Xray-URL-Speedtest
        if tcp_alive:
            port_queue = asyncio.Queue()
            for p in range(20000, 20000 + CONCURRENT_XRAY): port_queue.put_nowait(p)
                
            await asyncio.gather(*[test_proxy_with_xray(p, port_queue, xray_bin) for p in tcp_alive])

            # ЭЛИТА: Только те, кто скачал файл без EOF
            real_alive = [p for p in tcp_alive if p["latency"] < 9999.0]
            
            # Сортировка по Пингу (сначала самые быстрые)
            real_alive.sort(key=lambda x: (x["latency"], -x["speed_mbps"]))
            
            logger.info(f"🏆 Абсолютно живых, пробивающих блокировку серверов: {len(real_alive)} !!")
            
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                for node in real_alive:  # БЕЗ ЛИМИТОВ MAX_PROXIES!
                    base = node["link"].split('#')[0]
                    name_old = node["name"]
                    name_old = re.sub(r'^\[.*?\]\s*', '', name_old) # Стираем старые теги скоростей
                    if not name_old: name_old = f"Proxy {node['host']}"
                        
                    transport = {"tcp": "TCP", "grpc": "gRPC", "ws": "WS", "xhttp": "XHTTP", "splithttp": "XHTTP"}.get(node['type'], node['type'])
                    
                    # Генерируем красивое название: [142ms|19мб/с] Vless TCP | Name
                    new_name = urllib.parse.quote(f"[{node['latency']}ms|{node['speed_mbps']}мб/c] {node['proto']} {transport} | {name_old}")
                    f.write(f"{base}#{new_name}\n")
                    
            logger.info(f"🔥 УСПЕХ! ВЕСЬ безграничный список сохранен в {OUTPUT_FILE}!")
        else: logger.warning("В интернете не найдено ни одного живого IP. Мясорубка остановлена.")
    else: logger.warning("Парсер не нашел ни одной поддерживаемой ссылки.")

if __name__ == "__main__":
    if platform.system() == "Windows": asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
