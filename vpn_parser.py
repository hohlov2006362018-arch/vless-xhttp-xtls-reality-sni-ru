import asyncio
import aiohttp
import base64
import urllib.parse
import time
import re
import ipaddress
import logging

# Настройка логирования для красивого вывода в GitHub Actions
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Источники подписок (Sub links)
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
TCP_TIMEOUT_SECONDS = 3.0

def decode_base64_if_needed(content: str) -> str:
    """Умный декодер базы: проверяет, является ли строка Base64 списком, и декодирует его."""
    content = content.strip()
    if not content: return ""
    # Если строка начинает выглядеть как стандарнтный протокол, это сырой текст
    if "://" in content[:50]:
        return content
    try:
        # Добавляем паддинг, если его не хватает
        padded = content + "=" * ((4 - len(content) % 4) % 4)
        result = base64.b64decode(padded).decode('utf-8')
        return result
    except Exception:
        return content # Возвращаем как есть, если это просто сырой текст

def is_valid_ip_or_cidr(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def parse_and_filter_vless(link: str) -> dict:
    """
    Парсит конфигурацию и фильтрует по жестким критериям ТЗ:
    VLESS + XHTTP + Reality + SNI: *.ru + Host: Valid IP (условие CIDR)
    """
    link = link.strip()
    if not link.startswith("vless://"): return None
    
    try:
        parsed = urllib.parse.urlsplit(link)
        query = urllib.parse.parse_qs(parsed.query)
        
        # Разбираем хост и порт
        host_port = parsed.netloc.split('@')[-1]
        if ':' in host_port:
            host, port = host_port.rsplit(':', 1)
        else:
            return None

        # 1. Проверка XTLS Reality
        if query.get('security', [''])[0].lower() != 'reality': 
            return None
            
        # 2. Проверка XHTTP (или splithttp - новая номенклатура ядра)
        transport = query.get('type', [''])[0].lower()
        if transport not in ['xhttp', 'splithttp']:
            return None
            
        # 3. Проверка SNI на принадлежность RU сегменту
        sni = query.get('sni', [''])[0].lower()
        if not (sni.endswith('.ru') or '.ru' in sni):
            return None

        # 4. Проверка CIDR / IP (Хост должен быть прямым IP-адресом, а не заблокированным доменом)
        if not is_valid_ip_or_cidr(host):
            return None

        return {
            "link": link,
            "host": host,
            "port": int(port),
            "latency": 9999.0
        }
    except Exception:
        return None

async def fetch_source(session: aiohttp.ClientSession, url: str) -> list:
    """Асинхронно скачивает источник и возвращает список ссылок на прокси."""
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                text = await response.text()
                text = decode_base64_if_needed(text)
                return text.split('\n')
    except Exception as e:
        logger.debug(f"Ошибка при загрузке {url}: {e}")
    return[]

async def tcp_ping(proxy_data: dict, semaphore: asyncio.Semaphore):
    """Делает максимально быстрый асинхронный TCP пинг узла для замера задержки."""
    async with semaphore:
        start_time = time.monotonic()
        try:
            # Пытаемся открыть сокет-соединение к IP:Port сервера
            future = asyncio.open_connection(proxy_data["host"], proxy_data["port"])
            reader, writer = await asyncio.wait_for(future, timeout=TCP_TIMEOUT_SECONDS)
            
            latency = (time.monotonic() - start_time) * 1000  # Переводим в миллисекунды
            proxy_data["latency"] = latency
            
            writer.close()
            await writer.wait_closed()
        except Exception:
            # В случае тайм-аута или блока (ТСПУ) задержка остается высокой (мёртвый узел)
            proxy_data["latency"] = 9999.0

async def main():
    logger.info("Запуск VPN-парсера. Скачивание конфигов из интернет-источников...")
    
    # 1. Конкурентная загрузка со всех ссылок
    all_raw_lines = set()
    async with aiohttp.ClientSession() as session:
        tasks =[fetch_source(session, url) for url in SOURCES]
        results = await asyncio.gather(*tasks)
        for sublist in results:
            for line in sublist:
                all_raw_lines.add(line.strip())
                
    logger.info(f"Собрано уникальных строк/конфигов: {len(all_raw_lines)}")

    # 2. Фильтрация и парсинг по правилам
    valid_proxies =[]
    for line in all_raw_lines:
        parsed = parse_and_filter_vless(line)
        if parsed is not None:
            valid_proxies.append(parsed)

    logger.info(f"Прошли фильтрацию (VLESS+XHTTP+Reality+RU+CIDR): {len(valid_proxies)} шт.")

    # 3. Массовый параллельный Ping-Тест (Latency Test)
    if valid_proxies:
        logger.info("Запуск TCP Ping Test для проверки доступности (обход РКН)...")
        # Ограничиваем до 500 одновременных сокетов, чтобы не получить бан по сети
        semaphore = asyncio.Semaphore(500) 
        ping_tasks = [tcp_ping(p, semaphore) for p in valid_proxies]
        await asyncio.gather(*ping_tasks)

        # Выкидываем те, что не прошли пинг, и сортируем по задержке
        alive_proxies = [p for p in valid_proxies if p["latency"] < 9999.0]
        alive_proxies.sort(key=lambda x: x["latency"])
        
        # Обрезаем до 250 лучших (исходя из ТЗ)
        best_proxies = alive_proxies[:MAX_PROXIES]
        
        logger.info(f"Тест завершен. Живых узлов найдено: {len(alive_proxies)}. Вывод {len(best_proxies)} лучших.")
        
        # 4. Сохранение результата
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for node in best_proxies:
                # Добавляем тег скорости (задержки) к имени для наглядности
                link = node["link"]
                # Заменяем старое имя узла форматом: [Ping ms] OriginalName
                link = re.sub(r'#(.*)$', f'#[{int(node["latency"])}ms] \\1', link)
                f.write(link + "\n")
                
        logger.info(f"Файл успешно сохранен: {OUTPUT_FILE}")
    else:
        logger.warning("Не найдено узлов, подходящих под жесткие критерии.")

if __name__ == "__main__":
    asyncio.run(main())
