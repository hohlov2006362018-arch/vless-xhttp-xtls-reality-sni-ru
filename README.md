# 👻 TheDarkGhost's VPN: Ultimate VLESS Reality Aggregator

<p align="center">
  <img src="https://img.shields.io/github/stars/hohlov2006362018-arch/vless-xhttp-xtls-reality-sni-ru?style=for-the-badge&color=blueviolet" alt="Stars">
  <img src="https://img.shields.io/badge/Auto--Update-Every%2012h-blue?style=for-the-badge" alt="Update">
  <img src="https://img.shields.io/badge/License-GPLv3-green?style=for-the-badge" alt="License">
</p>

---

## 🚀 О проекте
**TheDarkGhost's VPN** — это высокотехнологичный инструмент для автоматического сбора, глубокой фильтрации и оптимизации VLESS Reality конфигураций. Проект создан специально для обхода самых суровых систем DPI (ТСПУ) и обеспечения стабильного доступа в интернет.

### Основные фишки:
* **Reality + Vision:** Сбор только самых современных и скрытных протоколов.
* **RU-CIDR-SNI Optimization:** Автоматическая подмена SNI-CIDR на популярные российские ресурсы для маскировки трафика.
* **Smart Filtering:** Скрипт проверяет серверы на доступность и отсеивает мусор.
* **Auto-pilot:** Полное обновление базы каждые 12 часов через GitHub Actions.
* **Full Hiddify Support:** Поддержка подписки с отображением статистики (6767 ГБ).

---

## 🛠 Быстрый старт (Hiddify / NekoBox / v2rayN)

Самый простой способ использовать — добавить ссылку как подписку.

1.  Скопируй ссылку на подписку:
    `https://thedarkghostsvpn.hohlov2006362018.workers.dev/`
2.  Открой **Hiddify** (или свой клиент).
3.  Нажми **"Новый профиль"** -> **"Добавить из URL"**.
4.  Вставь скопированную ссылку.
5.  Наслаждайся! (И не забудь про 6767 ГБ статы 😎).

---

## 📦 Что под капотом?

Проект состоит из мощного Python-парсера, который:
1. Сканирует более 15 топовых агрегаторов.
2. Декодирует `base64` и извлекает чистые `vless://` ссылки.
3. Проверяет валидность и группирует ключи.
4. Применяет магию Cloudflare Workers для визуального оформления подписки.

***Готовые универсальные настройки Hiddify.***
```json
{
  "region": "ru",
  "block-ads": false,
  "use-xray-core-when-possible": true,
  "execute-config-as-is": false,
  "log-level": "warn",
  "resolve-destination": true,
  "ipv6-mode": "ipv4_only",
  "remote-dns-address": "https://cloudflare-dns.com/dns-query",
  "remote-dns-domain-strategy": "",
  "direct-dns-address": "https://77.88.8.8/dns-query",
  "direct-dns-domain-strategy": "",
  "mixed-port": 12334,
  "tproxy-port": 12335,
  "direct-port": 12337,
  "redirect-port": 12336,
  "tun-implementation": "gvisor",
  "mtu": 9000,
  "strict-route": true,
  "connection-test-url": "https://www.speedtest.net",
  "url-test-interval": 600,
  "enable-clash-api": true,
  "clash-api-port": 16756,
  "enable-tun": true,
  "enable-tun-service": false,
  "set-system-proxy": false,
  "bypass-lan": true,
  "allow-connection-from-lan": true,
  "enable-fake-dns": true,
  "independent-dns-cache": true,
  "rules": [],
  "mux": {
    "enable": false,
    "padding": false,
    "max-streams": 8,
    "protocol": "h2mux"
  },
  "tls-tricks": {
    "enable-fragment": true,
    "fragment-size": "1-3",
    "fragment-sleep": "10-20",
    "mixed-sni-case": true,
    "enable-padding": true,
    "padding-size": "100-1500"
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
