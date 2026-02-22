
> [!IMPORTANT]
> **❗ НАСТОЯТЕЛЬНО РЕКОМЕНДУЮ ИСПОЛЬЗОВАТЬ ПОДПИСКУ В HIDDIFY ❗**

---

### Шаг 2 — Настройка Hiddify `v4.0.4`

<details>
<summary><b>📖 Пошаговая инструкция по импорту</b></summary>

<br>

| Шаг | Действие |
|:---:|:---|
| **1** | Заходим в **Hiddify** |
| **2** | Ищем боковую кнопку `Настройки` *(интерфейс может различаться на разных платформах)* |
| **3** | Ищем **три точки** — должна быть опция, связанная с импортом |
| **4** | Нажимаем **«Импортировать настройки из буфера обмена»** |
| **5** | ✅ **ГОТОВО!** |

</details>

<details>
<summary><b>⚙️ Универсальные настройки для импорта (JSON)</b></summary>

<br>

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
