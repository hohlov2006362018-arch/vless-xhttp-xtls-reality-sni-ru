# 🚀 VLESS Reality + Vision + CIDR SNI | Ultimate Aggregator

[![GitHub Stars](https://img.shields.io/github/stars/hohlov2006362018-arch/vless-xhttp-xtls-reality-sni-ru?style=for-the-badge)](https://github.com/hohlov2006362018-arch/vless-xhttp-xtls-reality-sni-ru/stargazers)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge)](https://www.gnu.org/licenses/gpl-3.0)
[![Update](https://img.shields.io/badge/Auto--Update-Every%2012h-blueviolet?style=for-the-badge)](https://github.com/hohlov2006362018-arch/vless-xhttp-xtls-reality-sni-ru/actions)

**VLESS Reality Aggregator** — это высокотехнологичный инструмент для автоматического сбора, проверки и глубокой модификации VPN-конфигураций. Проект создан для обеспечения стабильного и быстрого доступа в интернет в условиях жесткой цензуры и работы систем ТСПУ (DPI).

---

## 💎 Почему это лучше обычных подписок?

Большинство агрегаторов просто копируют ссылки. Наш скрипт работает иначе:

* **Интеллектуальный фильтр:** Мы не просто проверяем «живой» ли сервер, мы анализируем его технические параметры.
* **Модернизация протокола:** Скрипт на лету исправляет устаревшие конфиги, принудительно добавляя `flow=xtls-rprx-vision`.
* **Маскировка под РФ:** Уникальная система подмены SNI на адреса из доверенных российских подсетей (**CIDR**).

---

## 🔥 Ключевые возможности

### 🛡 XTLS Reality + Vision Flow
Скрипт автоматически инжектирует параметр `flow=xtls-rprx-vision` во все совместимые TCP-конфигурации. 
> **Зачем это нужно?** Vision Flow предотвращает детектирование протокола по длине пакетов и защищает от активного сканирования. Это убирает предупреждения *"Deprecated feature"* в современных клиентах (v2rayN и др.).

### 📡 Маскировка SNI через CIDR
Возможность подмены стандартных доменов (вроде `google.com`) на IP-адреса из «белых» списков (подсети крупных российских компаний, госуслуг и т.д.).
* **Результат:** Для систем анализа ваш трафик выглядит как обращение к легитимным внутренним ресурсам.

### ⚡ Высокоскоростной TCP-Ping
Скрипт использует многопоточную проверку (**100+ потоков**). Каждый сервер проверяется на реальный отклик порта. Вы получаете только те ключи, которые действительно работают.

### 🌍 Умная сортировка и GeoIP
Интеграция с базой данных MaxMind позволяет:
* Определять **реальную страну** сервера.
* Автоматически добавлять флаг страны `[RU]`, `[DE]`, `[US]` в название конфига.
* Группировать сервера для удобного выбора.

---

## 🛠 Технологический стек

| Технология | Описание |
| :--- | :--- |
| **VLESS** | Самый современный беспатерный протокол без шифрования на уровне транспорта. |
| **Reality** | Позволяет серверу «красть» TLS-сертификат у любого разрешенного сайта. |
| **Vision** | Дополнение к VLESS, устраняющее типичные TLS-отпечатки. |
| **uTLS** | Имитация отпечатков браузеров (Chrome, Safari) для обхода Fingerprinting. |

---

## 📲 Быстрый старт

### Шаг 1: Получение ссылки
Скопируйте ссылку для импорта подписки:
```text
https://raw.githubusercontent.com/hohlov2006362018-arch/vless-xhttp-xtls-reality-sni-ru/main/best_ru_sni_reality.txt
```
**❗❗❗ НАСТОЯТЕЛЬНО РЕКОМЕНДУЮ ИСПОЛЬЗОВАТЬ ПОДПИСКУ В HIDDIFY ❗❗❗**

### **Шаг 2: Настройка Hiddify v4.0.4**

*1.* Заходим в Hiddify.
*2.* Ищем боковую кнопку `Настройки` *(Разные платформы, интерфейс может изменится)*
*3.* Ищем три точки и должно что-то быть связано с импортом.
*4.* Нажимаем `Импортировать настройки из буфера обмена`.
*5.* ГОТОВО!

Импорт подписки (универсальный):
```json
{
  "region": "ru",
  "block-ads": true,
  "use-xray-core-when-possible": false,
  "execute-config-as-is": false,
  "log-level": "warn",
  "resolve-destination": true,
  "ipv6-mode": "ipv4_only",
  "remote-dns-address": "https://1.1.1.1/dns-query",
  "remote-dns-domain-strategy": "ipv4_only",
  "direct-dns-address": "https://77.88.8.8/dns-query",
  "direct-dns-domain-strategy": "ipv4_only",
  "mixed-port": 12334,
  "tproxy-port": 12335,
  "direct-port": 12337,
  "redirect-port": 12336,
  "tun-implementation": "system",
  "mtu": 9000,
  "strict-route": true,
  "connection-test-url": "http://cp.cloudflare.com",
  "url-test-interval": 600,
  "enable-clash-api": true,
  "clash-api-port": 16756,
  "enable-tun": true,
  "enable-tun-service": false,
  "set-system-proxy": false,
  "bypass-lan": true,
  "allow-connection-from-lan": false,
  "enable-fake-dns": true,
  "independent-dns-cache": true,
  "rules": [],
  "mux": {
    "enable": true,
    "padding": true,
    "max-streams": 8,
    "protocol": "h2mux"
  },
  "tls-tricks": {
    "enable-fragment": true,
    "fragment-size": "10-20",
    "fragment-sleep": "10-20",
    "mixed-sni-case": true,
    "enable-padding": true,
    "padding-size": "1-1500"
  },
  "warp": {
    "enable": false,
    "mode": "warp_over_proxy",
    "wireguard-config": "",
    "license-key": "",
    "account-id": "",
    "access-token": "",
    "clean-ip": "auto",
    "clean-port": 0,
    "noise": "1-3",
    "noise-size": "10-30",
    "noise-delay": "10-30",
    "noise-mode": "m4"
  },
  "warp2": {
    "enable": false,
    "mode": "warp_over_proxy",
    "wireguard-config": "",
    "license-key": "",
    "account-id": "",
    "access-token": "",
    "clean-ip": "auto",
    "clean-port": 0,
    "noise": "1-3",
    "noise-size": "10-30",
    "noise-delay": "10-30",
    "noise-mode": "m4"
  }
}
```

---

## ❓ Частые проблемы и их решения

**1. Hiddify автоматически выбирает прокси, а мне это не нравится.**
> **Решение:** После подключения на главном экране появляется кнопка ручного выбора прокси (иконка стрелки или надпись *Proxy/Прокси*). Нажмите на неё и выберите нужный сервер вручную (лучше выбирать тот, который уже запинговался).

**2. Прокси не работает (нет подключения).**
> **Решение:** Скорее всего, дело в блокировках провайдера. Попробуйте поменять настройки DNS, включить фрагментацию или настроить маршрутизацию. Если не знаете, как это сделать — не стесняйтесь спрашивать у нейросетей (ИИ отлично помогает с подбором параметров под конкретного провайдера).

**3. Не импортируется ссылка на подписку.**
> **Решение:** Обычно это происходит из-за того, что ваш провайдер блокирует доступ к серверу с подпиской (особенно часто это бывает на мобильном интернете). Попробуйте загрузить подписку через домашний Wi-Fi или предварительно включив другой рабочий VPN.
