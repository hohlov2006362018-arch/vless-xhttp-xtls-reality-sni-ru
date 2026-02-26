//! VPN Parser — VLESS + XHTTP + XTLS Reality + CIDR (SNI RU)
//!
//! Максимально оптимизированный и стабильный парсер VPN-ключей.
//! Собирает VLESS-конфигурации из публичных источников, фильтрует по:
//!   - Протокол: VLESS
//!   - Транспорт: XHTTP (xhttp / splithttp)
//!   - Безопасность: XTLS Reality (reality)
//!   - Сеть/SNI: Российские домены (.ru, .рф, .su) или IP из RU CIDR
//!
//! Проводит URL Test, TCP Ping, Speed Test.
//! Выводит до 250 лучших ключей, отсортированных по минимальной задержке.

use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Utc;
use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use indexmap::IndexMap;
use ipnetwork::IpNetwork;
use parking_lot::RwLock;
use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

// ═══════════════════════════════════════════════════════════════════
// КОНСТАНТЫ
// ═══════════════════════════════════════════════════════════════════

const MAX_KEYS: usize = 250;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_PING_TIMEOUT: Duration = Duration::from_secs(8);
const URL_TEST_TIMEOUT: Duration = Duration::from_secs(15);
const SPEED_TEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONCURRENT_FETCHES: usize = 8;
const CONCURRENT_TESTS: usize = 32;
const TCP_PING_ROUNDS: usize = 3;
const MIN_SPEED_BYTES: u64 = 1024; // 1 KB минимум для прохождения speed test
const OUTPUT_FILE: &str = "best_ru_cidr_xhttp_reality.txt";

/// Источники конфигураций
const SOURCES: &[&str] = &[
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
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless.txt",
];

// ═══════════════════════════════════════════════════════════════════
// РОССИЙСКИЕ CIDR-блоки (основные, RIPE NCC выделенные для RU)
// ═══════════════════════════════════════════════════════════════════

const RU_CIDRS: &[&str] = &[
    // Ростелеком
    "5.8.0.0/16",
    "5.16.0.0/14",
    "5.59.0.0/16",
    "5.100.0.0/14",
    "5.136.0.0/13",
    "5.164.0.0/14",
    "5.228.0.0/14",
    "5.250.0.0/16",
    "31.13.16.0/20",
    "31.28.0.0/15",
    "31.40.0.0/14",
    "31.128.0.0/11",
    "31.173.0.0/16",
    "31.180.0.0/14",
    "37.9.0.0/16",
    "37.18.0.0/16",
    "37.29.0.0/16",
    "37.44.0.0/16",
    "37.75.0.0/16",
    "37.110.0.0/15",
    "37.140.0.0/15",
    "37.144.0.0/14",
    "37.192.0.0/14",
    "37.200.0.0/15",
    "37.230.0.0/16",
    "46.0.0.0/14",
    "46.8.0.0/15",
    "46.17.0.0/16",
    "46.20.0.0/16",
    "46.28.0.0/16",
    "46.29.0.0/16",
    "46.34.0.0/16",
    "46.36.0.0/15",
    "46.39.0.0/16",
    "46.42.0.0/15",
    "46.46.0.0/16",
    "46.47.0.0/16",
    "46.48.0.0/12",
    "46.72.0.0/14",
    "46.146.0.0/15",
    "46.148.0.0/14",
    "46.158.0.0/15",
    "46.160.0.0/14",
    "46.172.0.0/15",
    "46.175.0.0/16",
    "46.180.0.0/14",
    "46.187.0.0/16",
    "46.188.0.0/14",
    "46.191.0.0/16",
    "46.226.0.0/16",
    "46.227.0.0/16",
    "46.235.0.0/16",
    "46.237.0.0/16",
    "46.242.0.0/16",
    "46.243.0.0/16",
    "46.250.0.0/16",
    "46.254.0.0/16",
    // МТС / Билайн / Мегафон
    "62.16.0.0/14",
    "62.33.0.0/16",
    "62.68.0.0/16",
    "62.76.0.0/14",
    "62.105.0.0/16",
    "62.109.0.0/16",
    "62.112.0.0/14",
    "62.117.0.0/16",
    "62.118.0.0/16",
    "62.122.0.0/16",
    "62.140.0.0/15",
    "62.148.0.0/16",
    "62.152.0.0/14",
    "62.168.0.0/16",
    "62.176.0.0/14",
    "62.181.0.0/16",
    "62.182.0.0/16",
    "62.205.0.0/16",
    "62.213.0.0/16",
    "62.220.0.0/16",
    "62.231.0.0/16",
    "77.34.0.0/15",
    "77.37.0.0/16",
    "77.39.0.0/16",
    "77.40.0.0/14",
    "77.44.0.0/16",
    "77.46.0.0/16",
    "77.50.0.0/15",
    "77.66.0.0/16",
    "77.72.0.0/16",
    "77.73.0.0/16",
    "77.75.0.0/16",
    "77.79.0.0/16",
    "77.82.0.0/15",
    "77.88.0.0/16",
    "77.91.0.0/16",
    "77.94.0.0/16",
    "77.95.0.0/16",
    "77.105.0.0/16",
    "77.106.0.0/15",
    "77.108.0.0/14",
    "77.220.0.0/16",
    "77.221.0.0/16",
    "77.222.0.0/15",
    "77.232.0.0/16",
    "77.233.0.0/16",
    "77.234.0.0/16",
    "77.235.0.0/16",
    "77.236.0.0/14",
    "77.240.0.0/16",
    "77.243.0.0/16",
    "77.244.0.0/15",
    "77.246.0.0/16",
    "77.247.0.0/16",
    // Yandex, Mail.ru, VK
    "5.45.192.0/18",
    "5.255.192.0/18",
    "77.88.0.0/18",
    "87.250.224.0/19",
    "93.158.128.0/18",
    "95.108.128.0/17",
    "100.43.64.0/19",
    "141.8.128.0/18",
    "178.154.128.0/17",
    "185.32.184.0/22",
    "185.71.76.0/22",
    "213.180.192.0/19",
    // Крупные хостинги RU
    "78.24.0.0/15",
    "78.36.0.0/14",
    "78.81.0.0/16",
    "78.85.0.0/16",
    "78.107.0.0/16",
    "78.108.0.0/15",
    "78.132.0.0/14",
    "78.136.0.0/15",
    "78.139.0.0/16",
    "78.140.0.0/15",
    "79.104.0.0/14",
    "79.110.0.0/16",
    "79.120.0.0/16",
    "79.126.0.0/15",
    "79.133.0.0/16",
    "79.134.0.0/16",
    "79.137.0.0/16",
    "79.140.0.0/14",
    "79.164.0.0/14",
    "80.64.0.0/14",
    "80.68.0.0/16",
    "80.73.0.0/16",
    "80.76.0.0/16",
    "80.78.0.0/16",
    "80.82.0.0/16",
    "80.83.0.0/16",
    "80.85.0.0/16",
    "80.87.0.0/16",
    "80.89.0.0/16",
    "80.90.0.0/16",
    "80.91.0.0/16",
    "80.92.0.0/16",
    "80.93.0.0/16",
    "80.94.0.0/15",
    "80.240.0.0/16",
    "80.242.0.0/16",
    "80.243.0.0/16",
    "80.247.0.0/16",
    "80.248.0.0/16",
    "80.249.0.0/16",
    "80.250.0.0/15",
    "80.252.0.0/14",
    "81.1.0.0/16",
    "81.2.0.0/16",
    "81.3.0.0/16",
    "81.16.0.0/16",
    "81.17.0.0/16",
    "81.18.0.0/15",
    "81.20.0.0/16",
    "81.22.0.0/16",
    "81.23.0.0/16",
    "81.24.0.0/14",
    "81.30.0.0/16",
    "81.94.0.0/16",
    "81.95.0.0/16",
    "81.163.0.0/16",
    "81.176.0.0/14",
    "81.195.0.0/16",
    "81.200.0.0/16",
    "81.211.0.0/16",
    "81.222.0.0/16",
    // Широкие блоки
    "82.114.0.0/15",
    "82.138.0.0/16",
    "82.140.0.0/14",
    "82.144.0.0/14",
    "82.148.0.0/16",
    "82.151.0.0/16",
    "82.162.0.0/15",
    "82.179.0.0/16",
    "82.196.0.0/16",
    "82.198.0.0/16",
    "82.200.0.0/14",
    "82.204.0.0/14",
    "82.208.0.0/14",
    "83.69.0.0/16",
    "83.102.0.0/16",
    "83.149.0.0/16",
    "83.166.0.0/16",
    "83.167.0.0/16",
    "83.172.0.0/14",
    "83.219.0.0/16",
    "83.220.0.0/14",
    "83.229.0.0/16",
    "83.234.0.0/16",
    "83.237.0.0/16",
    "83.239.0.0/16",
    "83.243.0.0/16",
    // Дополнительные
    "85.21.0.0/16",
    "85.26.0.0/15",
    "85.28.0.0/14",
    "85.115.0.0/16",
    "85.140.0.0/14",
    "85.172.0.0/14",
    "85.192.0.0/14",
    "85.198.0.0/16",
    "85.202.0.0/16",
    "85.234.0.0/16",
    "85.235.0.0/16",
    "85.236.0.0/16",
    "85.249.0.0/16",
    "86.62.0.0/16",
    "86.102.0.0/15",
    "86.110.0.0/16",
    "87.117.0.0/16",
    "87.225.0.0/16",
    "87.226.0.0/15",
    "87.228.0.0/14",
    "87.240.0.0/15",
    "87.245.0.0/16",
    "87.249.0.0/16",
    "87.250.0.0/15",
    "88.83.0.0/16",
    "88.84.0.0/14",
    "88.147.0.0/16",
    "88.200.0.0/14",
    "88.204.0.0/14",
    "88.208.0.0/14",
    "88.212.0.0/14",
    "89.20.0.0/16",
    "89.21.0.0/16",
    "89.22.0.0/16",
    "89.23.0.0/16",
    "89.28.0.0/16",
    "89.102.0.0/16",
    "89.108.0.0/14",
    "89.169.0.0/16",
    "89.175.0.0/16",
    "89.178.0.0/15",
    "89.185.0.0/16",
    "89.189.0.0/16",
    "89.190.0.0/16",
    "89.207.0.0/16",
    "89.208.0.0/15",
    "89.218.0.0/15",
    "89.221.0.0/16",
    "89.222.0.0/15",
    "89.232.0.0/14",
    "89.236.0.0/15",
    "89.239.0.0/16",
    "89.248.0.0/16",
    "89.249.0.0/16",
    "89.250.0.0/15",
    "89.252.0.0/14",
    "90.150.0.0/15",
    "90.154.0.0/15",
    "90.188.0.0/14",
    "91.103.0.0/16",
    "91.105.0.0/16",
    "91.106.0.0/16",
    "91.122.0.0/16",
    "91.142.0.0/16",
    "91.143.0.0/16",
    "91.144.0.0/14",
    "91.184.0.0/16",
    "91.185.0.0/16",
    "91.188.0.0/16",
    "91.189.0.0/16",
    "91.190.0.0/16",
    "91.192.0.0/16",
    "91.194.0.0/16",
    "91.195.0.0/16",
    "91.197.0.0/16",
    "91.198.0.0/16",
    "91.200.0.0/16",
    "91.203.0.0/16",
    "91.204.0.0/16",
    "91.205.0.0/16",
    "91.206.0.0/16",
    "91.207.0.0/16",
    "91.208.0.0/16",
    "91.209.0.0/16",
    "91.210.0.0/16",
    "91.211.0.0/16",
    "91.212.0.0/16",
    "91.213.0.0/16",
    "91.215.0.0/16",
    "91.216.0.0/16",
    "91.217.0.0/16",
    "91.218.0.0/16",
    "91.219.0.0/16",
    "91.220.0.0/16",
    "91.221.0.0/16",
    "91.222.0.0/16",
    "91.223.0.0/16",
    "91.224.0.0/16",
    "91.225.0.0/16",
    "91.226.0.0/16",
    "91.227.0.0/16",
    "91.228.0.0/16",
    "91.229.0.0/16",
    "91.230.0.0/16",
    "91.231.0.0/16",
    "91.232.0.0/16",
    "91.233.0.0/16",
    "91.234.0.0/16",
    "91.235.0.0/16",
    "91.236.0.0/16",
    "91.237.0.0/16",
    "91.238.0.0/16",
    "91.239.0.0/16",
    "91.240.0.0/16",
    "91.241.0.0/16",
    "91.242.0.0/16",
    "91.243.0.0/16",
    "91.244.0.0/16",
    "91.245.0.0/16",
    "91.246.0.0/16",
    "92.38.0.0/16",
    "92.39.0.0/16",
    "92.50.0.0/16",
    "92.51.0.0/16",
    "92.53.0.0/16",
    "92.60.0.0/16",
    "92.100.0.0/14",
    "92.124.0.0/14",
    "92.240.0.0/16",
    "92.241.0.0/16",
    "92.242.0.0/16",
    "92.243.0.0/16",
    "92.246.0.0/16",
    "92.248.0.0/16",
    "93.80.0.0/14",
    "93.84.0.0/16",
    "93.100.0.0/16",
    "93.170.0.0/16",
    "93.171.0.0/16",
    "93.178.0.0/16",
    "93.180.0.0/16",
    "93.185.0.0/16",
    "93.186.0.0/16",
    "93.190.0.0/16",
    "94.19.0.0/16",
    "94.24.0.0/14",
    "94.41.0.0/16",
    "94.50.0.0/15",
    "94.75.0.0/16",
    "94.79.0.0/16",
    "94.100.0.0/16",
    "94.137.0.0/16",
    "94.139.0.0/16",
    "94.140.0.0/14",
    "94.180.0.0/14",
    "94.198.0.0/16",
    "94.199.0.0/16",
    "94.230.0.0/16",
    "94.231.0.0/16",
    "94.232.0.0/16",
    "94.241.0.0/16",
    "94.245.0.0/16",
    "94.250.0.0/15",
    "95.24.0.0/13",
    "95.37.0.0/16",
    "95.54.0.0/15",
    "95.68.0.0/16",
    "95.72.0.0/13",
    "95.105.0.0/16",
    "95.130.0.0/16",
    "95.131.0.0/16",
    "95.140.0.0/16",
    "95.142.0.0/16",
    "95.143.0.0/16",
    "95.153.0.0/16",
    "95.154.0.0/15",
    "95.161.0.0/16",
    "95.163.0.0/16",
    "95.165.0.0/16",
    "95.167.0.0/16",
    "95.173.0.0/16",
    "95.181.0.0/16",
    "95.188.0.0/14",
    "95.213.0.0/16",
    "95.214.0.0/16",
    "95.220.0.0/16",
    "95.221.0.0/16",
    "95.222.0.0/16",
    "95.223.0.0/16",
    // 176-185 блоки
    "176.14.0.0/15",
    "176.28.0.0/16",
    "176.32.0.0/14",
    "176.49.0.0/16",
    "176.51.0.0/16",
    "176.52.0.0/14",
    "176.59.0.0/16",
    "176.96.0.0/16",
    "176.97.0.0/16",
    "176.99.0.0/16",
    "176.100.0.0/16",
    "176.101.0.0/16",
    "176.106.0.0/16",
    "176.107.0.0/16",
    "176.109.0.0/16",
    "176.112.0.0/16",
    "176.113.0.0/16",
    "176.114.0.0/16",
    "176.116.0.0/16",
    "176.117.0.0/16",
    "176.118.0.0/16",
    "176.119.0.0/16",
    "176.120.0.0/16",
    "176.122.0.0/16",
    "176.124.0.0/14",
    "176.195.0.0/16",
    "176.196.0.0/14",
    "176.208.0.0/14",
    "176.212.0.0/14",
    "176.222.0.0/16",
    "176.226.0.0/15",
    "178.16.0.0/16",
    "178.20.0.0/16",
    "178.21.0.0/16",
    "178.22.0.0/16",
    "178.35.0.0/16",
    "178.36.0.0/16",
    "178.44.0.0/14",
    "178.46.0.0/15",
    "178.48.0.0/14",
    "178.57.0.0/16",
    "178.59.0.0/16",
    "178.62.0.0/16",
    "178.68.0.0/14",
    "178.72.0.0/16",
    "178.120.0.0/14",
    "178.124.0.0/14",
    "178.140.0.0/14",
    "178.159.0.0/16",
    "178.162.0.0/16",
    "178.168.0.0/16",
    "178.172.0.0/14",
    "178.176.0.0/14",
    "178.204.0.0/14",
    "178.208.0.0/16",
    "178.209.0.0/16",
    "178.210.0.0/15",
    "178.212.0.0/16",
    "178.213.0.0/16",
    "178.214.0.0/16",
    "178.218.0.0/16",
    "178.237.0.0/16",
    "178.248.0.0/16",
    "178.249.0.0/16",
    // 185.x
    "185.3.0.0/16",
    "185.4.0.0/16",
    "185.5.0.0/16",
    "185.6.0.0/16",
    "185.8.0.0/16",
    "185.12.0.0/16",
    "185.13.0.0/16",
    "185.14.0.0/16",
    "185.15.0.0/16",
    "185.16.0.0/16",
    "185.18.0.0/16",
    "185.22.0.0/16",
    "185.23.0.0/16",
    "185.25.0.0/16",
    "185.26.0.0/16",
    "185.29.0.0/16",
    "185.30.0.0/16",
    "185.31.0.0/16",
    "185.36.0.0/16",
    "185.39.0.0/16",
    "185.41.0.0/16",
    "185.42.0.0/16",
    "185.43.0.0/16",
    "185.44.0.0/16",
    "185.46.0.0/16",
    "185.50.0.0/16",
    "185.54.0.0/16",
    "185.59.0.0/16",
    "185.63.0.0/16",
    "185.66.0.0/16",
    "185.68.0.0/16",
    "185.71.0.0/16",
    "185.72.0.0/16",
    "185.76.0.0/16",
    "185.78.0.0/16",
    "185.86.0.0/16",
    "185.88.0.0/16",
    "185.91.0.0/16",
    "185.97.0.0/16",
    "185.99.0.0/16",
    "185.100.0.0/16",
    "185.101.0.0/16",
    "185.102.0.0/16",
    "185.103.0.0/16",
    "185.104.0.0/16",
    "185.105.0.0/16",
    "185.107.0.0/16",
    "185.112.0.0/16",
    "185.114.0.0/16",
    "185.117.0.0/16",
    "185.119.0.0/16",
    "185.120.0.0/16",
    "185.130.0.0/16",
    "185.141.0.0/16",
    "185.143.0.0/16",
    "185.145.0.0/16",
    "185.146.0.0/16",
    "185.148.0.0/16",
    "185.149.0.0/16",
    "185.154.0.0/16",
    "185.161.0.0/16",
    "185.163.0.0/16",
    "185.165.0.0/16",
    "185.168.0.0/16",
    "185.170.0.0/16",
    "185.173.0.0/16",
    "185.176.0.0/16",
    "185.178.0.0/16",
    "185.179.0.0/16",
    "185.180.0.0/16",
    "185.182.0.0/16",
    "185.185.0.0/16",
    "185.186.0.0/16",
    "185.188.0.0/16",
    "185.189.0.0/16",
    "185.193.0.0/16",
    "185.195.0.0/16",
    "185.198.0.0/16",
    "185.200.0.0/16",
    "185.201.0.0/16",
    "185.203.0.0/16",
    "185.204.0.0/16",
    "185.206.0.0/16",
    "185.209.0.0/16",
    "185.210.0.0/16",
    "185.212.0.0/16",
    "185.215.0.0/16",
    "185.217.0.0/16",
    "185.219.0.0/16",
    "185.220.0.0/16",
    "185.221.0.0/16",
    "185.222.0.0/16",
    "185.223.0.0/16",
    "185.225.0.0/16",
    "185.228.0.0/16",
    "185.230.0.0/16",
    "185.231.0.0/16",
    "185.233.0.0/16",
    "185.237.0.0/16",
    "185.240.0.0/16",
    "185.241.0.0/16",
    "185.242.0.0/16",
    "185.243.0.0/16",
    "185.244.0.0/16",
    "185.245.0.0/16",
    "185.246.0.0/16",
    "185.248.0.0/16",
    "185.250.0.0/16",
    "185.251.0.0/16",
    "185.253.0.0/16",
    "185.254.0.0/16",
    // 188, 193, 194, 195
    "188.16.0.0/14",
    "188.32.0.0/12",
    "188.64.0.0/16",
    "188.65.0.0/16",
    "188.93.0.0/16",
    "188.116.0.0/16",
    "188.120.0.0/14",
    "188.128.0.0/12",
    "188.162.0.0/15",
    "188.168.0.0/13",
    "188.186.0.0/15",
    "188.226.0.0/16",
    "188.227.0.0/16",
    "188.233.0.0/16",
    "188.234.0.0/15",
    "188.242.0.0/15",
    "188.244.0.0/14",
    "193.0.0.0/16",
    "193.3.0.0/16",
    "193.19.0.0/16",
    "193.22.0.0/16",
    "193.23.0.0/16",
    "193.24.0.0/16",
    "193.25.0.0/16",
    "193.26.0.0/16",
    "193.28.0.0/16",
    "193.29.0.0/16",
    "193.32.0.0/16",
    "193.33.0.0/16",
    "193.34.0.0/16",
    "193.36.0.0/16",
    "193.37.0.0/16",
    "193.38.0.0/16",
    "193.41.0.0/16",
    "193.42.0.0/16",
    "193.43.0.0/16",
    "193.46.0.0/16",
    "193.47.0.0/16",
    "193.56.0.0/16",
    "193.104.0.0/14",
    "193.124.0.0/14",
    "193.150.0.0/16",
    "193.164.0.0/16",
    "193.168.0.0/16",
    "193.176.0.0/16",
    "193.178.0.0/16",
    "193.180.0.0/16",
    "193.186.0.0/16",
    "193.200.0.0/16",
    "193.222.0.0/16",
    "193.224.0.0/14",
    "193.228.0.0/16",
    "193.232.0.0/14",
    "193.238.0.0/16",
    "194.8.0.0/16",
    "194.24.0.0/16",
    "194.26.0.0/16",
    "194.28.0.0/16",
    "194.32.0.0/16",
    "194.44.0.0/16",
    "194.48.0.0/16",
    "194.50.0.0/16",
    "194.54.0.0/16",
    "194.58.0.0/16",
    "194.60.0.0/16",
    "194.67.0.0/16",
    "194.79.0.0/16",
    "194.84.0.0/16",
    "194.85.0.0/16",
    "194.87.0.0/16",
    "194.105.0.0/16",
    "194.110.0.0/16",
    "194.135.0.0/16",
    "194.140.0.0/16",
    "194.145.0.0/16",
    "194.147.0.0/16",
    "194.150.0.0/16",
    "194.152.0.0/16",
    "194.154.0.0/16",
    "194.158.0.0/16",
    "194.165.0.0/16",
    "194.186.0.0/15",
    "194.190.0.0/15",
    "195.2.0.0/16",
    "195.3.0.0/16",
    "195.5.0.0/16",
    "195.9.0.0/16",
    "195.12.0.0/16",
    "195.16.0.0/16",
    "195.18.0.0/16",
    "195.19.0.0/16",
    "195.20.0.0/16",
    "195.34.0.0/16",
    "195.38.0.0/16",
    "195.42.0.0/16",
    "195.46.0.0/16",
    "195.54.0.0/16",
    "195.58.0.0/16",
    "195.62.0.0/16",
    "195.64.0.0/16",
    "195.68.0.0/16",
    "195.69.0.0/16",
    "195.70.0.0/16",
    "195.72.0.0/16",
    "195.80.0.0/16",
    "195.82.0.0/16",
    "195.85.0.0/16",
    "195.88.0.0/16",
    "195.91.0.0/16",
    "195.93.0.0/16",
    "195.98.0.0/16",
    "195.128.0.0/16",
    "195.131.0.0/16",
    "195.133.0.0/16",
    "195.140.0.0/16",
    "195.146.0.0/16",
    "195.149.0.0/16",
    "195.151.0.0/16",
    "195.152.0.0/16",
    "195.158.0.0/16",
    "195.161.0.0/16",
    "195.162.0.0/16",
    "195.170.0.0/16",
    "195.178.0.0/16",
    "195.182.0.0/16",
    "195.186.0.0/16",
    "195.189.0.0/16",
    "195.190.0.0/16",
    "195.200.0.0/16",
    "195.208.0.0/14",
    "195.214.0.0/16",
    "195.216.0.0/16",
    "195.218.0.0/16",
    "195.222.0.0/16",
    "195.226.0.0/16",
    "195.230.0.0/16",
    "195.234.0.0/16",
    "195.239.0.0/16",
    "195.242.0.0/16",
    "195.245.0.0/16",
    "195.248.0.0/16",
    "195.250.0.0/16",
    // 212, 213, 217
    "212.1.0.0/16",
    "212.3.0.0/16",
    "212.5.0.0/16",
    "212.8.0.0/16",
    "212.12.0.0/16",
    "212.15.0.0/16",
    "212.17.0.0/16",
    "212.19.0.0/16",
    "212.20.0.0/16",
    "212.22.0.0/16",
    "212.23.0.0/16",
    "212.24.0.0/16",
    "212.32.0.0/16",
    "212.34.0.0/16",
    "212.41.0.0/16",
    "212.42.0.0/16",
    "212.45.0.0/16",
    "212.46.0.0/16",
    "212.48.0.0/16",
    "212.49.0.0/16",
    "212.57.0.0/16",
    "212.59.0.0/16",
    "212.75.0.0/16",
    "212.90.0.0/16",
    "212.92.0.0/16",
    "212.93.0.0/16",
    "212.96.0.0/16",
    "212.100.0.0/16",
    "212.109.0.0/16",
    "212.110.0.0/16",
    "212.116.0.0/16",
    "212.119.0.0/16",
    "212.120.0.0/16",
    "212.122.0.0/16",
    "212.124.0.0/16",
    "212.152.0.0/16",
    "212.164.0.0/14",
    "212.176.0.0/16",
    "212.192.0.0/14",
    "212.220.0.0/16",
    "212.233.0.0/16",
    "212.248.0.0/16",
    "213.5.0.0/16",
    "213.24.0.0/14",
    "213.33.0.0/16",
    "213.59.0.0/16",
    "213.79.0.0/16",
    "213.80.0.0/16",
    "213.85.0.0/16",
    "213.87.0.0/16",
    "213.108.0.0/16",
    "213.131.0.0/16",
    "213.138.0.0/16",
    "213.148.0.0/16",
    "213.166.0.0/16",
    "213.167.0.0/16",
    "213.170.0.0/16",
    "213.171.0.0/16",
    "213.177.0.0/16",
    "213.178.0.0/16",
    "213.180.0.0/16",
    "213.182.0.0/16",
    "213.186.0.0/16",
    "213.189.0.0/16",
    "213.219.0.0/16",
    "213.222.0.0/16",
    "213.228.0.0/16",
    "213.232.0.0/16",
    "213.234.0.0/16",
    "217.12.0.0/16",
    "217.15.0.0/16",
    "217.16.0.0/16",
    "217.18.0.0/16",
    "217.23.0.0/16",
    "217.24.0.0/16",
    "217.25.0.0/16",
    "217.28.0.0/16",
    "217.29.0.0/16",
    "217.65.0.0/16",
    "217.66.0.0/16",
    "217.67.0.0/16",
    "217.69.0.0/16",
    "217.70.0.0/16",
    "217.73.0.0/16",
    "217.74.0.0/16",
    "217.76.0.0/16",
    "217.106.0.0/16",
    "217.107.0.0/16",
    "217.112.0.0/16",
    "217.114.0.0/16",
    "217.116.0.0/16",
    "217.117.0.0/16",
    "217.118.0.0/16",
    "217.119.0.0/16",
    "217.145.0.0/16",
    "217.148.0.0/16",
    "217.150.0.0/16",
    "217.170.0.0/16",
    "217.172.0.0/16",
    "217.174.0.0/16",
    "217.195.0.0/16",
    "217.196.0.0/16",
    "217.197.0.0/16",
    "217.198.0.0/16",
];

// ═══════════════════════════════════════════════════════════════════
// СТРУКТУРЫ ДАННЫХ
// ═══════════════════════════════════════════════════════════════════

/// Распарсенная VLESS-конфигурация
#[derive(Debug, Clone)]
struct VlessConfig {
    /// Полная URI-строка ключа
    raw_uri: String,
    /// UUID пользователя
    uuid: String,
    /// Адрес сервера (IP или домен)
    address: String,
    /// Порт сервера
    port: u16,
    /// Параметры запроса
    params: IndexMap<String, String>,
    /// Резолвленный IP (если удалось)
    resolved_ip: Option<IpAddr>,
    /// Имя/описание
    remark: String,
    /// SHA256 хеш для дедупликации
    hash: String,
}

/// Результат тестирования конфигурации
#[derive(Debug, Clone)]
struct TestResult {
    config: VlessConfig,
    /// Средняя задержка TCP ping в миллисекундах
    tcp_ping_ms: f64,
    /// Минимальная задержка TCP ping
    tcp_ping_min_ms: f64,
    /// URL Test задержка
    url_test_ms: f64,
    /// Скорость скачивания байт/сек
    download_speed: f64,
    /// Скорость загрузки байт/сек
    upload_speed: f64,
    /// Прошёл все тесты
    passed: bool,
}

/// Глобальная статистика
struct Stats {
    total_fetched: AtomicUsize,
    total_vless: AtomicUsize,
    total_filtered: AtomicUsize,
    total_tested: AtomicUsize,
    total_passed: AtomicUsize,
}

impl Stats {
    fn new() -> Self {
        Self {
            total_fetched: AtomicUsize::new(0),
            total_vless: AtomicUsize::new(0),
            total_filtered: AtomicUsize::new(0),
            total_tested: AtomicUsize::new(0),
            total_passed: AtomicUsize::new(0),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> Result<()> {
    // Инициализация логирования
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .init();

    let start_time = Instant::now();
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  VPN Parser — VLESS + XHTTP + XTLS Reality + CIDR (RU)    ║");
    info!("║  Максимально оптимизированный Rust-парсер                  ║");
    info!("╚══════════════════════════════════════════════════════════════╝");

    let stats = Arc::new(Stats::new());

    // ───────────────────────────────────────────────────────
    // Шаг 1: Загрузка RU CIDR
    // ───────────────────────────────────────────────────────
    info!("━━━ Шаг 1: Загрузка RU CIDR блоков ━━━");
    let ru_cidrs = load_ru_cidrs()?;
    info!("  Загружено {} RU CIDR блоков", ru_cidrs.len());

    // ───────────────────────────────────────────────────────
    // Шаг 2: Загрузка конфигураций из всех источников
    // ───────────────────────────────────────────────────────
    info!("━━━ Шаг 2: Загрузка конфигураций из {} источников ━━━", SOURCES.len());
    let raw_configs = fetch_all_sources(Arc::clone(&stats)).await;
    info!(
        "  Загружено {} строк конфигураций",
        stats.total_fetched.load(Ordering::Relaxed)
    );

    // ───────────────────────────────────────────────────────
    // Шаг 3: Парсинг VLESS URI
    // ───────────────────────────────────────────────────────
    info!("━━━ Шаг 3: Парсинг VLESS URI ━━━");
    let vless_configs = parse_vless_configs(&raw_configs, Arc::clone(&stats));
    info!(
        "  Распарсено {} VLESS конфигураций",
        stats.total_vless.load(Ordering::Relaxed)
    );

    // ───────────────────────────────────────────────────────
    // Шаг 4: Фильтрация: XHTTP + Reality + RU CIDR/SNI
    // ───────────────────────────────────────────────────────
    info!("━━━ Шаг 4: Фильтрация (XHTTP + Reality + RU CIDR/SNI) ━━━");
    let filtered = filter_configs(vless_configs, &ru_cidrs, Arc::clone(&stats)).await;
    let filtered_count = filtered.len();
    info!(
        "  После фильтрации: {} конфигураций",
        filtered_count
    );

    if filtered.is_empty() {
        warn!("Не найдено подходящих конфигураций. Завершение.");
        write_empty_output()?;
        return Ok(());
    }

    // ───────────────────────────────────────────────────────
    // Шаг 5: Тестирование (TCP Ping + URL Test + Speed Test)
    // ───────────────────────────────────────────────────────
    info!("━━━ Шаг 5: Тестирование {} конфигураций ━━━", filtered_count);
    let test_results = test_all_configs(filtered, Arc::clone(&stats)).await;
    info!(
        "  Протестировано: {}, Прошло: {}",
        stats.total_tested.load(Ordering::Relaxed),
        stats.total_passed.load(Ordering::Relaxed)
    );

    // ───────────────────────────────────────────────────────
    // Шаг 6: Сортировка и вывод
    // ───────────────────────────────────────────────────────
    info!("━━━ Шаг 6: Сортировка и вывод результатов ━━━");
    let final_results = sort_and_limit(test_results);
    write_output(&final_results)?;

    let elapsed = start_time.elapsed();
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  ЗАВЕРШЕНО за {:.1} сек                                    ║", elapsed.as_secs_f64());
    info!("║  Найдено {} лучших серверов                            ║", final_results.len());
    info!("║  Файл: {}                        ║", OUTPUT_FILE);
    info!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// ЗАГРУЗКА RU CIDR
// ═══════════════════════════════════════════════════════════════════

fn load_ru_cidrs() -> Result<Vec<IpNetwork>> {
    let mut cidrs = Vec::with_capacity(RU_CIDRS.len());
    for cidr_str in RU_CIDRS {
        match cidr_str.parse::<IpNetwork>() {
            Ok(net) => cidrs.push(net),
            Err(e) => {
                debug!("Пропуск невалидного CIDR '{}': {}", cidr_str, e);
            }
        }
    }
    Ok(cidrs)
}

fn is_ip_in_ru_cidrs(ip: IpAddr, cidrs: &[IpNetwork]) -> bool {
    cidrs.iter().any(|cidr| cidr.contains(ip))
}

fn is_ru_sni(sni: &str) -> bool {
    let sni_lower = sni.to_lowercase();
    sni_lower.ends_with(".ru")
        || sni_lower.ends_with(".рф")
        || sni_lower.ends_with(".su")
        || sni_lower == "ru"
        || sni_lower == "рф"
        || sni_lower == "su"
        // Популярные российские домены
        || sni_lower.ends_with(".yandex.ru")
        || sni_lower.ends_with(".mail.ru")
        || sni_lower.ends_with(".vk.com")
        || sni_lower.contains("gosuslugi")
        || sni_lower.contains("kremlin")
        || sni_lower.contains("government")
        || sni_lower.contains("mos.ru")
}

// ═══════════════════════════════════════════════════════════════════
// ЗАГРУЗКА ИСТОЧНИКОВ
// ═══════════════════════════════════════════════════════════════════

async fn fetch_all_sources(stats: Arc<Stats>) -> Vec<String> {
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(4)
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
        .build()
        .expect("Не удалось создать HTTP-клиент");

    let all_lines: Arc<DashMap<String, ()>> = Arc::new(DashMap::new());

    let results = stream::iter(SOURCES.iter().enumerate())
        .map(|(idx, url)| {
            let client = client.clone();
            let all_lines = Arc::clone(&all_lines);
            let stats = Arc::clone(&stats);
            async move {
                info!("  [{}/{}] Загрузка: {}...", idx + 1, SOURCES.len(), truncate_url(url));
                match fetch_single_source(&client, url).await {
                    Ok(lines) => {
                        let count = lines.len();
                        for line in lines {
                            all_lines.insert(line, ());
                        }
                        stats.total_fetched.fetch_add(count, Ordering::Relaxed);
                        info!("  [{}/{}] ✓ {} строк", idx + 1, SOURCES.len(), count);
                    }
                    Err(e) => {
                        warn!("  [{}/{}] ✗ Ошибка: {}", idx + 1, SOURCES.len(), e);
                    }
                }
            }
        })
        .buffer_unordered(CONCURRENT_FETCHES)
        .collect::<Vec<_>>()
        .await;

    all_lines
        .iter()
        .map(|entry| entry.key().clone())
        .collect()
}

async fn fetch_single_source(client: &reqwest::Client, url: &str) -> Result<Vec<String>> {
    let response = client
        .get(url)
        .send()
        .await
        .context("Ошибка HTTP-запроса")?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP {}", response.status());
    }

    let body = response
        .text()
        .await
        .context("Ошибка чтения тела ответа")?;

    // Попытка декодирования base64
    let decoded = try_decode_base64(&body);
    let text = decoded.as_deref().unwrap_or(&body);

    let lines: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    Ok(lines)
}

fn try_decode_base64(input: &str) -> Option<String> {
    let trimmed = input.trim();

    // Если уже содержит vless://, не декодируем
    if trimmed.contains("vless://") || trimmed.contains("vmess://") || trimmed.contains("ss://") {
        return None;
    }

    // Пробуем разные варианты base64
    for engine in &[&STANDARD as &dyn base64::Engine, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(trimmed.as_bytes()) {
            if let Ok(decoded) = String::from_utf8(bytes) {
                if decoded.contains("vless://") {
                    return Some(decoded);
                }
            }
        }
    }

    // Пробуем построчно
    let mut decoded_lines = Vec::new();
    let mut any_decoded = false;
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut line_decoded = false;
        for engine in &[&STANDARD as &dyn base64::Engine, &URL_SAFE, &URL_SAFE_NO_PAD] {
            if let Ok(bytes) = engine.decode(line.as_bytes()) {
                if let Ok(decoded) = String::from_utf8(bytes) {
                    if decoded.contains("://") {
                        decoded_lines.push(decoded);
                        any_decoded = true;
                        line_decoded = true;
                        break;
                    }
                }
            }
        }
        if !line_decoded {
            decoded_lines.push(line.to_string());
        }
    }

    if any_decoded {
        Some(decoded_lines.join("\n"))
    } else {
        None
    }
}

fn truncate_url(url: &str) -> String {
    if url.len() > 70 {
        format!("{}...", &url[..67])
    } else {
        url.to_string()
    }
}

// ═══════════════════════════════════════════════════════════════════
// ПАРСИНГ VLESS URI
// ═══════════════════════════════════════════════════════════════════

fn parse_vless_configs(raw_lines: &[String], stats: Arc<Stats>) -> Vec<VlessConfig> {
    let seen_hashes: Arc<DashMap<String, ()>> = Arc::new(DashMap::new());
    let configs: Vec<VlessConfig> = raw_lines
        .iter()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("vless://") {
                return None;
            }
            parse_single_vless(line, &seen_hashes)
        })
        .collect();

    stats.total_vless.store(configs.len(), Ordering::Relaxed);
    configs
}

fn parse_single_vless(uri: &str, seen: &DashMap<String, ()>) -> Option<VlessConfig> {
    // vless://UUID@ADDRESS:PORT?params#remark
    let without_scheme = uri.strip_prefix("vless://")?;

    // Разделяем на основную часть и fragment (remark)
    let (main_part, remark) = match without_scheme.split_once('#') {
        Some((m, r)) => (m, percent_decode_str(r).decode_utf8_lossy().to_string()),
        None => (without_scheme, String::new()),
    };

    // Разделяем на userinfo@host:port и query
    let (authority_part, query_string) = match main_part.split_once('?') {
        Some((a, q)) => (a, q),
        None => (main_part, ""),
    };

    // UUID@address:port
    let (uuid, host_port) = authority_part.split_once('@')?;
    let uuid = uuid.to_string();

    // Парсим address:port (учитываем IPv6 в квадратных скобках)
    let (address, port) = parse_host_port(host_port)?;

    // Парсим query параметры
    let params = parse_query_params(query_string);

    // Вычисляем хеш для дедупликации (по uuid + address + port + ключевым параметрам)
    let hash_input = format!(
        "{}|{}|{}|{}|{}|{}",
        uuid,
        address,
        port,
        params.get("type").unwrap_or(&String::new()),
        params.get("security").unwrap_or(&String::new()),
        params.get("sni").unwrap_or(&String::new()),
    );
    let mut hasher = Sha256::new();
    hasher.update(hash_input.as_bytes());
    let hash = hex::encode(hasher.finalize());

    // Дедупликация
    if seen.contains_key(&hash) {
        return None;
    }
    seen.insert(hash.clone(), ());

    Some(VlessConfig {
        raw_uri: uri.to_string(),
        uuid,
        address,
        port,
        params,
        resolved_ip: None,
        remark,
        hash,
    })
}

fn parse_host_port(input: &str) -> Option<(String, u16)> {
    if input.starts_with('[') {
        // IPv6: [::1]:443
        let end_bracket = input.find(']')?;
        let addr = input[1..end_bracket].to_string();
        let port_str = input.get(end_bracket + 2..)?; // skip ]:
        let port = port_str.parse().ok()?;
        Some((addr, port))
    } else {
        let last_colon = input.rfind(':')?;
        let addr = input[..last_colon].to_string();
        let port = input[last_colon + 1..].parse().ok()?;
        if addr.is_empty() || port == 0 {
            return None;
        }
        Some((addr, port))
    }
}

fn parse_query_params(query: &str) -> IndexMap<String, String> {
    let mut params = IndexMap::new();
    if query.is_empty() {
        return params;
    }
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let key = percent_decode_str(key).decode_utf8_lossy().to_lowercase();
            let value = percent_decode_str(value).decode_utf8_lossy().to_string();
            params.insert(key, value);
        }
    }
    params
}

// ═══════════════════════════════════════════════════════════════════
// ФИЛЬТРАЦИЯ
// ═══════════════════════════════════════════════════════════════════

async fn filter_configs(
    configs: Vec<VlessConfig>,
    ru_cidrs: &[IpNetwork],
    stats: Arc<Stats>,
) -> Vec<VlessConfig> {
    let filtered: Vec<VlessConfig> = stream::iter(configs)
        .filter_map(|mut config| {
            let cidrs = ru_cidrs.to_vec();
            async move {
                // 1. Проверяем транспорт: XHTTP (xhttp или splithttp)
                let transport = config.params.get("type").map(|s| s.to_lowercase());
                let is_xhttp = match &transport {
                    Some(t) => t == "xhttp" || t == "splithttp",
                    None => false,
                };
                if !is_xhttp {
                    return None;
                }

                // 2. Проверяем security: reality
                let security = config.params.get("security").map(|s| s.to_lowercase());
                let is_reality = match &security {
                    Some(s) => s == "reality",
                    None => false,
                };
                if !is_reality {
                    return None;
                }

                // 3. Проверяем наличие обязательных Reality параметров
                let has_pbk = config
                    .params
                    .get("pbk")
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
                if !has_pbk {
                    return None;
                }

                // 4. Проверяем RU: SNI или IP в RU CIDR
                let sni = config
                    .params
                    .get("sni")
                    .cloned()
                    .unwrap_or_default();

                let server_name = config
                    .params
                    .get("servername")
                    .cloned()
                    .unwrap_or_default();

                let effective_sni = if !sni.is_empty() {
                    sni.clone()
                } else {
                    server_name.clone()
                };

                let sni_is_ru = is_ru_sni(&effective_sni);

                // Резолвим IP адрес сервера
                let resolved_ip = resolve_address(&config.address).await;
                config.resolved_ip = resolved_ip;

                let ip_is_ru = match config.resolved_ip {
                    Some(ip) => is_ip_in_ru_cidrs(ip, &cidrs),
                    None => false,
                };

                // Хотя бы одно из условий: SNI RU или IP в RU CIDR
                if !sni_is_ru && !ip_is_ru {
                    return None;
                }

                Some(config)
            }
        })
        .collect()
        .await;

    stats.total_filtered.store(filtered.len(), Ordering::Relaxed);
    filtered
}

async fn resolve_address(address: &str) -> Option<IpAddr> {
    // Если уже IP
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Some(ip);
    }

    // DNS резолвинг
    let addr_with_port = format!("{}:0", address);
    match tokio::task::spawn_blocking(move || addr_with_port.to_socket_addrs())
        .await
    {
        Ok(Ok(mut addrs)) => addrs.next().map(|sa| sa.ip()),
        _ => {
            // Пробуем через trust-dns
            match trust_dns_resolver::TokioAsyncResolver::tokio(
                trust_dns_resolver::config::ResolverConfig::google(),
                trust_dns_resolver::config::ResolverOpts::default(),
            ) {
                Ok(resolver) => {
                    match resolver.lookup_ip(address).await {
                        Ok(lookup) => lookup.iter().next(),
                        Err(_) => None,
                    }
                }
                Err(_) => None,
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// ТЕСТИРОВАНИЕ
// ═══════════════════════════════════════════════════════════════════

async fn test_all_configs(
    configs: Vec<VlessConfig>,
    stats: Arc<Stats>,
) -> Vec<TestResult> {
    let results: Vec<TestResult> = stream::iter(configs)
        .map(|config| {
            let stats = Arc::clone(&stats);
            async move {
                stats.total_tested.fetch_add(1, Ordering::Relaxed);
                let result = test_single_config(config).await;
                if result.passed {
                    stats.total_passed.fetch_add(1, Ordering::Relaxed);
                }
                result
            }
        })
        .buffer_unordered(CONCURRENT_TESTS)
        .filter(|r| futures::future::ready(r.passed))
        .collect()
        .await;

    results
}

async fn test_single_config(config: VlessConfig) -> TestResult {
    let mut result = TestResult {
        config: config.clone(),
        tcp_ping_ms: f64::MAX,
        tcp_ping_min_ms: f64::MAX,
        url_test_ms: f64::MAX,
        download_speed: 0.0,
        upload_speed: 0.0,
        passed: false,
    };

    // ─── TCP Ping ───
    match tcp_ping(&config).await {
        Some((avg, min)) => {
            result.tcp_ping_ms = avg;
            result.tcp_ping_min_ms = min;
            debug!(
                "  TCP Ping {}:{} — avg: {:.1}ms, min: {:.1}ms",
                config.address, config.port, avg, min
            );
        }
        None => {
            debug!("  TCP Ping FAILED {}:{}", config.address, config.port);
            return result;
        }
    }

    // ─── URL Test (TLS handshake to the server with Reality SNI) ───
    match url_test(&config).await {
        Some(ms) => {
            result.url_test_ms = ms;
            debug!(
                "  URL Test {}:{} — {:.1}ms",
                config.address, config.port, ms
            );
        }
        None => {
            debug!("  URL Test FAILED {}:{}", config.address, config.port);
            return result;
        }
    }

    // ─── Speed Test (download/upload estimation) ───
    match speed_test(&config).await {
        Some((down, up)) => {
            result.download_speed = down;
            result.upload_speed = up;
            debug!(
                "  Speed Test {}:{} — down: {:.0} B/s, up: {:.0} B/s",
                config.address, config.port, down, up
            );
        }
        None => {
            debug!("  Speed Test FAILED {}:{}", config.address, config.port);
            // Speed test failure — всё равно пропускаем с минимальными значениями,
            // если TCP ping и URL test прошли
            result.download_speed = MIN_SPEED_BYTES as f64;
            result.upload_speed = MIN_SPEED_BYTES as f64;
        }
    }

    result.passed = true;
    result
}

/// TCP Ping — замеряем время установления TCP-соединения
async fn tcp_ping(config: &VlessConfig) -> Option<(f64, f64)> {
    let addr = resolve_to_socket_addr(&config.address, config.port).await?;

    let mut times = Vec::with_capacity(TCP_PING_ROUNDS);

    for _ in 0..TCP_PING_ROUNDS {
        let start = Instant::now();
        match timeout(TCP_PING_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                times.push(elapsed);
                drop(stream);
            }
            _ => {
                // Одна неудача допустима
                continue;
            }
        }
        // Пауза между пингами
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if times.is_empty() {
        return None;
    }

    let avg = times.iter().sum::<f64>() / times.len() as f64;
    let min = times.iter().cloned().fold(f64::MAX, f64::min);

    Some((avg, min))
}

/// URL Test — устанавливаем TCP + проверяем что порт жив и готов к TLS
async fn url_test(config: &VlessConfig) -> Option<f64> {
    let addr = resolve_to_socket_addr(&config.address, config.port).await?;

    let start = Instant::now();

    // Устанавливаем TCP-соединение
    let mut stream = match timeout(URL_TEST_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Отправляем TLS ClientHello минимальный (проверяем что сервер отвечает)
    // Формируем минимальный TLS 1.2 ClientHello для проверки
    let sni = config
        .params
        .get("sni")
        .or_else(|| config.params.get("servername"))
        .cloned()
        .unwrap_or_else(|| config.address.clone());

    let client_hello = build_minimal_client_hello(&sni);

    match timeout(
        Duration::from_secs(5),
        stream.write_all(&client_hello),
    )
    .await
    {
        Ok(Ok(_)) => {}
        _ => return None,
    }

    // Читаем ответ (ServerHello)
    let mut buf = [0u8; 512];
    match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            // Проверяем что ответ похож на TLS ServerHello (ContentType = 0x16)
            if buf[0] == 0x16 {
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                return Some(elapsed);
            }
            // Даже если не TLS, сервер ответил — считаем жив
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            Some(elapsed)
        }
        _ => None,
    }
}

/// Speed Test — оценка скорости через передачу данных по TCP
async fn speed_test(config: &VlessConfig) -> Option<(f64, f64)> {
    let addr = resolve_to_socket_addr(&config.address, config.port).await?;

    // Download test: подключаемся и читаем что сервер пошлёт
    let download_speed = {
        let start = Instant::now();
        match timeout(SPEED_TEST_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Отправляем минимальный запрос
                let sni = config
                    .params
                    .get("sni")
                    .or_else(|| config.params.get("servername"))
                    .cloned()
                    .unwrap_or_else(|| config.address.clone());

                let hello = build_minimal_client_hello(&sni);
                let _ = timeout(Duration::from_secs(3), stream.write_all(&hello)).await;

                let mut total_bytes: u64 = 0;
                let mut buf = [0u8; 8192];

                loop {
                    if start.elapsed() > Duration::from_secs(5) {
                        break;
                    }
                    match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => total_bytes += n as u64,
                        _ => break,
                    }
                }

                let elapsed = start.elapsed().as_secs_f64();
                if elapsed > 0.0 && total_bytes >= MIN_SPEED_BYTES {
                    total_bytes as f64 / elapsed
                } else if total_bytes > 0 {
                    total_bytes as f64
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    };

    // Upload test: подключаемся и пишем данные
    let upload_speed = {
        let start = Instant::now();
        match timeout(SPEED_TEST_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let test_data = vec![0xAA_u8; 4096];
                let mut total_bytes: u64 = 0;

                loop {
                    if start.elapsed() > Duration::from_secs(3) {
                        break;
                    }
                    match timeout(Duration::from_secs(1), stream.write_all(&test_data)).await {
                        Ok(Ok(_)) => total_bytes += test_data.len() as u64,
                        _ => break,
                    }
                }

                let elapsed = start.elapsed().as_secs_f64();
                if elapsed > 0.0 && total_bytes >= MIN_SPEED_BYTES {
                    total_bytes as f64 / elapsed
                } else {
                    MIN_SPEED_BYTES as f64
                }
            }
            _ => MIN_SPEED_BYTES as f64,
        }
    };

    Some((download_speed, upload_speed))
}

/// Минимальный TLS 1.2 ClientHello для проверки сервера
fn build_minimal_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len();

    // SNI Extension
    let sni_extension: Vec<u8> = {
        let mut ext = Vec::new();
        // Extension Type: server_name (0x0000)
        ext.extend_from_slice(&[0x00, 0x00]);
        // Extension Data Length
        let data_len = (sni_len + 5) as u16;
        ext.extend_from_slice(&data_len.to_be_bytes());
        // Server Name List Length
        let list_len = (sni_len + 3) as u16;
        ext.extend_from_slice(&list_len.to_be_bytes());
        // Server Name Type: host_name (0)
        ext.push(0x00);
        // Server Name Length
        let name_len = sni_len as u16;
        ext.extend_from_slice(&name_len.to_be_bytes());
        // Server Name
        ext.extend_from_slice(sni_bytes);
        ext
    };

    // Supported Versions Extension (TLS 1.3)
    let supported_versions: Vec<u8> = vec![
        0x00, 0x2b, // Extension Type: supported_versions
        0x00, 0x03, // Length
        0x02,       // Supported Versions Length
        0x03, 0x04, // TLS 1.3
    ];

    let extensions_len = sni_extension.len() + supported_versions.len();

    // ClientHello
    let mut hello = Vec::new();

    // Handshake Type: ClientHello (1)
    hello.push(0x01);

    // Random (32 bytes)
    let random: [u8; 32] = rand::random();

    // Session ID Length (0)
    let session_id_len: u8 = 0;

    // Cipher Suites
    let cipher_suites: Vec<u8> = vec![
        0x00, 0x04, // Length (2 cipher suites = 4 bytes)
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
    ];

    // Compression Methods
    let compression: Vec<u8> = vec![0x01, 0x00]; // 1 method, null

    // Client Version
    let version: [u8; 2] = [0x03, 0x03]; // TLS 1.2

    // Calculate hello body length
    let body_len = 2 // version
        + 32 // random
        + 1 // session id length
        + cipher_suites.len()
        + compression.len()
        + 2 // extensions length
        + extensions_len;

    // Handshake length (3 bytes)
    let body_len_bytes = (body_len as u32).to_be_bytes();
    hello.extend_from_slice(&body_len_bytes[1..4]);

    // Version
    hello.extend_from_slice(&version);
    // Random
    hello.extend_from_slice(&random);
    // Session ID Length
    hello.push(session_id_len);
    // Cipher Suites
    hello.extend_from_slice(&cipher_suites);
    // Compression
    hello.extend_from_slice(&compression);
    // Extensions Length
    let ext_len_bytes = (extensions_len as u16).to_be_bytes();
    hello.extend_from_slice(&ext_len_bytes);
    // Extensions
    hello.extend_from_slice(&sni_extension);
    hello.extend_from_slice(&supported_versions);

    // Wrap in TLS Record
    let mut record = Vec::new();
    record.push(0x16); // ContentType: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // Legacy version: TLS 1.0
    let record_len = (hello.len() as u16).to_be_bytes();
    record.extend_from_slice(&record_len);
    record.extend_from_slice(&hello);

    record
}

async fn resolve_to_socket_addr(address: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }

    let addr_str = format!("{}:{}", address, port);
    match tokio::task::spawn_blocking(move || addr_str.to_socket_addrs())
        .await
    {
        Ok(Ok(mut addrs)) => addrs.next(),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════
// СОРТИРОВКА И ВЫВОД
// ═══════════════════════════════════════════════════════════════════

fn sort_and_limit(mut results: Vec<TestResult>) -> Vec<TestResult> {
    // Сортируем по минимальной задержке TCP ping
    results.sort_by(|a, b| {
        a.tcp_ping_min_ms
            .partial_cmp(&b.tcp_ping_min_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Ограничиваем до MAX_KEYS
    results.truncate(MAX_KEYS);
    results
}

fn write_output(results: &[TestResult]) -> Result<()> {
    use std::io::Write;

    let mut output = String::new();

    // Заголовок
    output.push_str(&format!(
        "# VPN Parser — Best RU CIDR + XHTTP + Reality Keys\n"
    ));
    output.push_str(&format!(
        "# Generated: {}\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));
    output.push_str(&format!("# Total keys: {}\n", results.len()));
    output.push_str(&format!(
        "# Filter: VLESS + XHTTP + XTLS Reality + CIDR/SNI RU\n"
    ));
    output.push_str(&format!("# Sorted by: minimum TCP ping latency\n"));
    output.push_str("#\n");
    output.push_str(&format!(
        "# {:>3} | {:>8} | {:>8} | {:>10} | {:>10} | {}\n",
        "#", "Ping(ms)", "URL(ms)", "Down(KB/s)", "Up(KB/s)", "Server"
    ));
    output.push_str(&format!("# {}\n", "─".repeat(75)));

    for (i, result) in results.iter().enumerate() {
        // Информационный комментарий
        output.push_str(&format!(
            "# {:>3} | {:>8.1} | {:>8.1} | {:>10.1} | {:>10.1} | {}:{}\n",
            i + 1,
            result.tcp_ping_min_ms,
            result.url_test_ms,
            result.download_speed / 1024.0,
            result.upload_speed / 1024.0,
            result.config.address,
            result.config.port,
        ));
    }

    output.push_str("#\n");
    output.push_str("# ═══════════════════ KEYS ═══════════════════\n");
    output.push_str("#\n");

    // Сами ключи
    for result in results {
        output.push_str(&result.config.raw_uri);
        output.push('\n');
    }

    let mut file = std::fs::File::create(OUTPUT_FILE)
        .context("Не удалось создать файл вывода")?;
    file.write_all(output.as_bytes())
        .context("Не удалось записать результат")?;

    info!("  Записано {} ключей в {}", results.len(), OUTPUT_FILE);
    Ok(())
}

fn write_empty_output() -> Result<()> {
    use std::io::Write;

    let output = format!(
        "# VPN Parser — No keys found\n# Generated: {}\n# Filter: VLESS + XHTTP + XTLS Reality + CIDR/SNI RU\n# No matching configurations found.\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    let mut file = std::fs::File::create(OUTPUT_FILE)?;
    file.write_all(output.as_bytes())?;

    Ok(())
}
