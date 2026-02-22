# 👻 TheDarkGhost's VPN: Ultimate VLESS Reality Aggregator

<p align="center">
  <img src="https://img.shields.io/github/stars/hohlov2006362018-arch/vless-xhttp-xtls-reality-sni-ru?style=for-the-badge&color=blueviolet" alt="Stars">
  <img src="https://img.shields.io/github/actions/workflow/status/hohlov2006362018-arch/vless-xhttp-xtls-reality-sni-ru/update.yml?style=for-the-badge" alt="Build Status">
  <img src="https://img.shields.io/badge/Auto--Update-Every%2012h-blue?style=for-the-badge" alt="Update">
  <img src="https://img.shields.io/badge/License-GPLv3-green?style=for-the-badge" alt="License">
</p>

---

## 🚀 О проекте
**TheDarkGhost's VPN** — это высокотехнологичный инструмент для автоматического сбора, глубокой фильтрации и оптимизации VLESS Reality конфигураций. Проект создан специально для обхода самых суровых систем DPI (ТСПУ) и обеспечения стабильного доступа в интернет.

### Основные фишки:
* **Reality + Vision:** Сбор только самых современных и скрытных протоколов.
* **RU-SNI Optimization:** Автоматическая подмена SNI на популярные российские ресурсы для маскировки трафика.
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

## 🚦 Правильная настройка (Маршрутизация)

Чтобы российские сайты (Госуслуги, банки, Яндекс) открывались без проблем и пинговались, включи раздельное туннелирование:

### В Hiddify:
1. Зайди в **Settings** (Настройки) -> **Routing** (Маршрутизация).
2. В поле **Mode** выбери **Bypass LAN/RU** (Только заблокированные).
3. *Опционально:* В **Custom Rules** добавь `Direct` для `geoip:ru` и `geosite:ru`.

---

## 📦 Что под капотом?

Проект состоит из мощного Python-парсера, который:
1. Сканирует более 15 топовых агрегаторов.
2. Декодирует `base64` и извлекает чистые `vless://` ссылки.
3. Проверяет валидность и группирует ключи.
4. Применяет магию Cloudflare Workers для визуального оформления подписки.

### Для разработчиков:
Если хочешь запустить парсер локально:
```bash
git clone [https://github.com/hohlov2006362018-arch/vless-xhttp-xtls-reality-sni-ru.git](https://github.com/hohlov2006362018-arch/vless-xhttp-xtls-reality-sni-ru.git)
cd vless-xhttp-xtls-reality-sni-ru
pip install requests maxminddb
python vpn_parser.py
