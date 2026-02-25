import requests
import re
import urllib.parse
import base64
import asyncio
import time
import socket
import ipaddress
import bisect
from datetime import datetime

# --- НАСТРОЙКИ ---
MAX_CONNECTIONS = 500  # Кол-во одновременных потоков (идеально для GitHub Actions)
TIMEOUT = 5.0          # Таймаут (секунды) для пинга и DNS-резолва
TOP_N = 750            # Лимит лучших серверов в финальном файле

# Фильтры
REQUIRE_XHTTP = True   # Поставь True, если нужны СТРОГО xhttp сервера (иначе оставит любые VLESS Reality)

# --- ИСТОЧНИКИ ---
GITHUB_SOURCES = [
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
# Зеркала Nikita29a
GITHUB_SOURCES.extend([f"https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/{i}.txt" for i in range(1, 26)])

# Глобальный кэш для бинарного поиска IP
ru_ip_ranges = []

def load_ru_cidrs():
    """ Скачивает свежую базу подсетей РФ и строит Interval Tree для сверхбыстрого бинарного поиска """
    print("[*] Загрузка актуальных RU CIDR баз для фильтрации SNI...")
    try:
        r = requests.get("https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/ipwhitelist.txt", timeout=15)
        ranges = []
        for line in r.text.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    net = ipaddress.IPv4Network(line)
                    ranges.append((int(net.network_address), int(net.broadcast_address)))
                except Exception:
                    pass
                    
        # Сортируем и объединяем соседние/пересекающиеся подсети
        ranges.sort(key=lambda x: x[0])
        merged = []
        for current in ranges:
            if not merged:
                merged.append(current)
            else:
                prev = merged[-1]
                if current[0] <= prev[1] + 1:
                    merged[-1] = (prev[0], max(prev[1], current[1]))
                else:
                    merged.append(current)
                    
        global ru_ip_ranges
        ru_ip_ranges = merged
        print(f"[+] База РФ IP загружена и оптимизирована! ({len(ru_ip_ranges)} уникальных диапазонов)")
    except Exception as e:
        print(f"[-] Ошибка загрузки базы CIDR: {e}")

def is_ru_ip(ip_str):
    """ Проверяет, принадлежит ли IP к РФ за O(log N) с помощью бинарного поиска """
    if not ru_ip_ranges: return False
    try:
        ip_int = int(ipaddress.IPv4Address(ip_str))
    except Exception:
        return False
        
    idx = bisect.bisect_right(ru_ip_ranges, (ip_int, float('inf')))
    if idx > 0:
        start, end = ru_ip_ranges[idx - 1]
        if start <= ip_int <= end:
            return True
    return False

def fetch_links():
    print(f"[*] Сбор ссылок из {len(GITHUB_SOURCES)} источников...")
    links = set()
    session = requests.Session()
    
    for url in GITHUB_SOURCES:
        try:
            res = session.get(url, timeout=10)
            if res.status_code == 200:
                text = res.text
                if "vless://" not in text:
                    try:
                        # Добавляем паддинг для корректного декодирования Base64
                        padded = text.strip() + "=" * ((4 - len(text.strip()) % 4) % 4)
                        text = base64.b64decode(padded).decode('utf-8')
                    except Exception:
                        pass
                
                # Ищем только VLESS
                found = [match.group(0) for match in re.finditer(r'vless://[^\s<>"\']+', text)]
                links.update(found)
                if found: print(f"[+] {url}: найдено {len(found)}")
        except Exception:
            pass
            
    print(f"[*] Всего уникальных ссылок VLESS собрано: {len(links)}")
    return list(links)

async def check_proxy(link, semaphore):
    """ Асинхронно парсит, проверяет Reality, SNI CIDR и делает TCP Ping """
    async with semaphore:
        # --- 1. Парсинг и фильтрация Reality/XHTTP ---
        try:
            parsed = urllib.parse.urlparse(link)
            if parsed.scheme != 'vless': return None
            
            host = parsed.hostname
            port = parsed.port or 443
            qs = urllib.parse.parse_qs(parsed.query)
            
            # Проверка безопасности (строго Reality)
            if qs.get('security', [''])[0].lower() not in ['reality', 'xtls-reality']:
                return None
                
            # Проверка XHTTP (если включена настройка)
            if REQUIRE_XHTTP and qs.get('type', [''])[0].lower() != 'xhttp':
                return None
                
            sni = qs.get('sni', [''])[0]
            if not sni:
                sni = host  # Если SNI не указан, проверяем сам хост
                
        except Exception:
            return None
            
        # --- 2. Разрешение SNI в IP ---
        loop = asyncio.get_running_loop()
        try:
            # Асинхронный DNS резолвинг домена SNI
            res = await asyncio.wait_for(loop.getaddrinfo(sni, None, family=socket.AF_INET), timeout=TIMEOUT)
            sni_ips = [r[4][0] for r in res]
        except Exception:
            return None # Если домен не отвечает, узел мертв
            
        # --- 3. Проверка на RU CIDR ---
        if not any(is_ru_ip(ip) for ip in sni_ips):
            return None # SNI не ведет на российский IP
            
        # --- 4. Измерение задержки (TCP Ping) ---
        start_time = time.monotonic()
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=TIMEOUT)
            writer.close()
            await writer.wait_closed()
            
            latency = (time.monotonic() - start_time) * 1000 # мс
            return (link, latency)
        except Exception:
            return None # Порт закрыт / таймаут

async def run_all_tests(links):
    print(f"[*] Запускаем фильтрацию SNI и TCP-тест для {len(links)} узлов...")
    semaphore = asyncio.Semaphore(MAX_CONNECTIONS)
    tasks = [asyncio.create_task(check_proxy(link, semaphore)) for link in links]
            
    results = []
    total = len(tasks)
    completed = 0
    
    for f in asyncio.as_completed(tasks):
        res = await f
        completed += 1
        if res:
            results.append(res)
            
        if completed % 2000 == 0:
            print(f"[*] Обработано: {completed}/{total} | Найдено RU SNI Reality: {len(results)}")
            
    return results

async def main():
    load_ru_cidrs()
    if not ru_ip_ranges:
        print("[-] Прерывание работы из-за ошибки базы IP.")
        return

    links = fetch_links()
    if not links:
        print("[-] Не удалось собрать ссылки!")
        return

    # Запускаем асинхронную проверку (теперь через await)
    results = await run_all_tests(links)
    
    print(f"\n[*] Тестирование окончено. Идеальных серверов найдено: {len(results)}")
    
    # Сортировка по минимальному пингу
    results.sort(key=lambda x: x[1])
    top_proxies = results[:TOP_N]
    
    filename = "best_ru_sni_reality.txt"
    print(f"[*] Сохраняем ТОП-{len(top_proxies)} в файл {filename}...")
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# UPDATED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Protocol: VLESS Reality (RU SNI)\n")
        f.write(f"# Total parsed: {len(links)} | Filtered Alive: {len(results)}\n\n")
        
        for link, latency in top_proxies:
            parsed = urllib.parse.urlparse(link)
            old_name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Unknown"
            new_name = f"[{int(latency)}ms] {old_name}"
            
            if "#" in link:
                clean_link = link.split("#")[0]
                final_link = f"{clean_link}#{urllib.parse.quote(new_name)}"
            else:
                final_link = f"{link}#{urllib.parse.quote(new_name)}"
                
            f.write(final_link + "\n")
            
    print(f"[+] Готово! Файл {filename} успешно сгенерирован.")

if __name__ == "__main__":
    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        # Пытаемся понять, где запущен код
        loop = asyncio.get_running_loop()
        is_jupyter = True
    except RuntimeError:
        is_jupyter = False

    if is_jupyter:
        # Если это Jupyter/Colab, используем библиотеку nest_asyncio для решения конфликта
        import nest_asyncio
        nest_asyncio.apply()
        asyncio.run(main())
    else:
        # Если это GitHub Actions / Ubuntu консоль - используем стандартный запуск

        asyncio.run(main())



