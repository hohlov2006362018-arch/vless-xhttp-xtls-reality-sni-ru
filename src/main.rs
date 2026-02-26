//! VPN Parser v2 — VLESS + XHTTP + XTLS Reality + CIDR (SNI RU)
//!
//! Реальная проверка через xray-core: каждый ключ запускается как локальный
//! SOCKS5-прокси, через который проводится HTTP-запрос к внешнему тестовому URL.
//! Только ключи, через которые реально проходит трафик, попадают в итог.

use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Utc;
use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use indexmap::IndexMap;
use ipnetwork::IpNetwork;
use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════════════
// КОНСТАНТЫ
// ═══════════════════════════════════════════════════════════════════

const MAX_KEYS: usize = 250;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_PING_TIMEOUT: Duration = Duration::from_secs(6);
const XRAY_TEST_TIMEOUT: Duration = Duration::from_secs(20);
const XRAY_STARTUP_WAIT: Duration = Duration::from_millis(1500);
const CONCURRENT_FETCHES: usize = 10;
const CONCURRENT_TESTS: usize = 16;
const TCP_PING_ROUNDS: usize = 3;
const SOCKS_PORT_BASE: u16 = 20000;
const OUTPUT_FILE: &str = "best_ru_cidr_xhttp_reality.txt";

// Тестовые URL для проверки через прокси (маленькие, быстрые)
const TEST_URLS: &[&str] = &[
    "http://cp.cloudflare.com/",
    "http://www.gstatic.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
];

const SPEED_TEST_URL: &str = "http://speed.cloudflare.com/__down?bytes=500000";
const SPEED_TEST_UPLOAD_URL: &str = "http://speed.cloudflare.com/__up";

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

const RU_CIDRS: &[&str] = &[
    "5.8.0.0/16", "5.16.0.0/14", "5.59.0.0/16", "5.100.0.0/14",
    "5.136.0.0/13", "5.164.0.0/14", "5.228.0.0/14", "5.250.0.0/16",
    "5.45.192.0/18", "5.255.192.0/18",
    "31.13.16.0/20", "31.28.0.0/15", "31.40.0.0/14", "31.128.0.0/11",
    "31.173.0.0/16", "31.180.0.0/14",
    "37.9.0.0/16", "37.18.0.0/16", "37.29.0.0/16", "37.44.0.0/16",
    "37.75.0.0/16", "37.110.0.0/15", "37.140.0.0/15", "37.144.0.0/14",
    "37.192.0.0/14", "37.200.0.0/15", "37.230.0.0/16",
    "46.0.0.0/14", "46.8.0.0/15", "46.17.0.0/16", "46.20.0.0/16",
    "46.28.0.0/16", "46.29.0.0/16", "46.34.0.0/16", "46.36.0.0/15",
    "46.39.0.0/16", "46.42.0.0/15", "46.46.0.0/16", "46.47.0.0/16",
    "46.48.0.0/12", "46.72.0.0/14", "46.146.0.0/15", "46.148.0.0/14",
    "46.158.0.0/15", "46.160.0.0/14", "46.172.0.0/15", "46.175.0.0/16",
    "46.180.0.0/14", "46.187.0.0/16", "46.188.0.0/14", "46.191.0.0/16",
    "46.226.0.0/16", "46.227.0.0/16", "46.235.0.0/16", "46.237.0.0/16",
    "46.242.0.0/16", "46.243.0.0/16", "46.250.0.0/16", "46.254.0.0/16",
    "62.16.0.0/14", "62.33.0.0/16", "62.68.0.0/16", "62.76.0.0/14",
    "62.105.0.0/16", "62.109.0.0/16", "62.112.0.0/14", "62.117.0.0/16",
    "62.118.0.0/16", "62.122.0.0/16", "62.140.0.0/15", "62.148.0.0/16",
    "62.152.0.0/14", "62.168.0.0/16", "62.176.0.0/14", "62.181.0.0/16",
    "62.182.0.0/16", "62.205.0.0/16", "62.213.0.0/16", "62.220.0.0/16",
    "77.34.0.0/15", "77.37.0.0/16", "77.39.0.0/16", "77.40.0.0/14",
    "77.44.0.0/16", "77.46.0.0/16", "77.50.0.0/15", "77.66.0.0/16",
    "77.72.0.0/16", "77.73.0.0/16", "77.75.0.0/16", "77.79.0.0/16",
    "77.82.0.0/15", "77.88.0.0/16", "77.88.0.0/18", "77.91.0.0/16",
    "77.94.0.0/16", "77.95.0.0/16", "77.105.0.0/16", "77.106.0.0/15",
    "77.108.0.0/14", "77.220.0.0/16", "77.221.0.0/16", "77.222.0.0/15",
    "77.232.0.0/16", "77.233.0.0/16", "77.234.0.0/16", "77.235.0.0/16",
    "77.236.0.0/14", "77.240.0.0/16", "77.243.0.0/16", "77.244.0.0/15",
    "77.246.0.0/16", "77.247.0.0/16",
    "78.24.0.0/15", "78.36.0.0/14", "78.81.0.0/16", "78.85.0.0/16",
    "78.107.0.0/16", "78.108.0.0/15", "78.132.0.0/14", "78.136.0.0/15",
    "78.139.0.0/16", "78.140.0.0/15",
    "79.104.0.0/14", "79.110.0.0/16", "79.120.0.0/16", "79.126.0.0/15",
    "79.133.0.0/16", "79.134.0.0/16", "79.137.0.0/16", "79.140.0.0/14",
    "79.164.0.0/14",
    "80.64.0.0/14", "80.68.0.0/16", "80.73.0.0/16", "80.76.0.0/16",
    "80.78.0.0/16", "80.82.0.0/16", "80.83.0.0/16", "80.85.0.0/16",
    "80.87.0.0/16", "80.89.0.0/16", "80.90.0.0/16", "80.91.0.0/16",
    "80.92.0.0/16", "80.93.0.0/16", "80.94.0.0/15", "80.240.0.0/16",
    "80.242.0.0/16", "80.243.0.0/16", "80.247.0.0/16", "80.248.0.0/16",
    "80.249.0.0/16", "80.250.0.0/15", "80.252.0.0/14",
    "81.1.0.0/16", "81.2.0.0/16", "81.3.0.0/16", "81.16.0.0/16",
    "81.17.0.0/16", "81.18.0.0/15", "81.20.0.0/16", "81.22.0.0/16",
    "81.23.0.0/16", "81.24.0.0/14", "81.30.0.0/16", "81.94.0.0/16",
    "81.95.0.0/16", "81.163.0.0/16", "81.176.0.0/14", "81.195.0.0/16",
    "81.200.0.0/16", "81.211.0.0/16", "81.222.0.0/16",
    "82.114.0.0/15", "82.138.0.0/16", "82.140.0.0/14", "82.144.0.0/14",
    "82.148.0.0/16", "82.151.0.0/16", "82.162.0.0/15", "82.179.0.0/16",
    "82.196.0.0/16", "82.198.0.0/16", "82.200.0.0/14", "82.204.0.0/14",
    "82.208.0.0/14",
    "83.69.0.0/16", "83.102.0.0/16", "83.149.0.0/16", "83.166.0.0/16",
    "83.167.0.0/16", "83.172.0.0/14", "83.219.0.0/16", "83.220.0.0/14",
    "83.229.0.0/16", "83.234.0.0/16", "83.237.0.0/16", "83.239.0.0/16",
    "85.21.0.0/16", "85.26.0.0/15", "85.28.0.0/14", "85.115.0.0/16",
    "85.140.0.0/14", "85.172.0.0/14", "85.192.0.0/14", "85.198.0.0/16",
    "85.202.0.0/16", "85.234.0.0/16", "85.235.0.0/16", "85.236.0.0/16",
    "86.62.0.0/16", "86.102.0.0/15", "86.110.0.0/16",
    "87.117.0.0/16", "87.225.0.0/16", "87.226.0.0/15", "87.228.0.0/14",
    "87.240.0.0/15", "87.245.0.0/16", "87.249.0.0/16", "87.250.0.0/15",
    "87.250.224.0/19",
    "88.83.0.0/16", "88.84.0.0/14", "88.147.0.0/16", "88.200.0.0/14",
    "88.204.0.0/14", "88.208.0.0/14", "88.212.0.0/14",
    "89.20.0.0/16", "89.21.0.0/16", "89.22.0.0/16", "89.23.0.0/16",
    "89.28.0.0/16", "89.102.0.0/16", "89.108.0.0/14", "89.169.0.0/16",
    "89.175.0.0/16", "89.178.0.0/15", "89.185.0.0/16", "89.189.0.0/16",
    "89.190.0.0/16", "89.207.0.0/16", "89.208.0.0/15", "89.221.0.0/16",
    "89.222.0.0/15", "89.232.0.0/14", "89.236.0.0/15", "89.239.0.0/16",
    "89.248.0.0/16", "89.249.0.0/16", "89.250.0.0/15", "89.252.0.0/14",
    "90.150.0.0/15", "90.154.0.0/15", "90.188.0.0/14",
    "91.103.0.0/16", "91.105.0.0/16", "91.106.0.0/16", "91.122.0.0/16",
    "91.142.0.0/16", "91.143.0.0/16", "91.144.0.0/14", "91.184.0.0/16",
    "91.185.0.0/16", "91.188.0.0/16", "91.189.0.0/16", "91.190.0.0/16",
    "91.192.0.0/16", "91.194.0.0/16", "91.195.0.0/16", "91.197.0.0/16",
    "91.198.0.0/16", "91.200.0.0/16", "91.203.0.0/16", "91.204.0.0/16",
    "91.205.0.0/16", "91.206.0.0/16", "91.207.0.0/16", "91.208.0.0/16",
    "91.209.0.0/16", "91.210.0.0/16", "91.211.0.0/16", "91.212.0.0/16",
    "91.213.0.0/16", "91.215.0.0/16", "91.216.0.0/16", "91.217.0.0/16",
    "91.218.0.0/16", "91.219.0.0/16", "91.220.0.0/16", "91.221.0.0/16",
    "91.222.0.0/16", "91.223.0.0/16", "91.224.0.0/16", "91.225.0.0/16",
    "91.226.0.0/16", "91.227.0.0/16", "91.228.0.0/16", "91.229.0.0/16",
    "91.230.0.0/16", "91.231.0.0/16", "91.232.0.0/16", "91.233.0.0/16",
    "91.234.0.0/16", "91.235.0.0/16", "91.236.0.0/16", "91.237.0.0/16",
    "91.238.0.0/16", "91.239.0.0/16", "91.240.0.0/16", "91.241.0.0/16",
    "91.242.0.0/16", "91.243.0.0/16", "91.244.0.0/16", "91.245.0.0/16",
    "92.38.0.0/16", "92.39.0.0/16", "92.50.0.0/16", "92.51.0.0/16",
    "92.53.0.0/16", "92.60.0.0/16", "92.100.0.0/14", "92.124.0.0/14",
    "92.240.0.0/16", "92.241.0.0/16", "92.242.0.0/16", "92.243.0.0/16",
    "92.246.0.0/16", "92.248.0.0/16",
    "93.80.0.0/14", "93.84.0.0/16", "93.100.0.0/16", "93.158.128.0/18",
    "93.170.0.0/16", "93.171.0.0/16", "93.178.0.0/16", "93.180.0.0/16",
    "93.185.0.0/16", "93.186.0.0/16", "93.190.0.0/16",
    "94.19.0.0/16", "94.24.0.0/14", "94.41.0.0/16", "94.50.0.0/15",
    "94.75.0.0/16", "94.79.0.0/16", "94.100.0.0/16", "94.137.0.0/16",
    "94.139.0.0/16", "94.140.0.0/14", "94.180.0.0/14", "94.198.0.0/16",
    "94.199.0.0/16", "94.230.0.0/16", "94.231.0.0/16", "94.232.0.0/16",
    "94.241.0.0/16", "94.245.0.0/16", "94.250.0.0/15",
    "95.24.0.0/13", "95.37.0.0/16", "95.54.0.0/15", "95.68.0.0/16",
    "95.72.0.0/13", "95.105.0.0/16", "95.108.128.0/17",
    "95.130.0.0/16", "95.131.0.0/16", "95.140.0.0/16", "95.142.0.0/16",
    "95.143.0.0/16", "95.153.0.0/16", "95.154.0.0/15", "95.161.0.0/16",
    "95.163.0.0/16", "95.165.0.0/16", "95.167.0.0/16", "95.173.0.0/16",
    "95.181.0.0/16", "95.188.0.0/14", "95.213.0.0/16", "95.214.0.0/16",
    "95.220.0.0/16", "95.221.0.0/16", "95.222.0.0/16", "95.223.0.0/16",
    "100.43.64.0/19", "141.8.128.0/18",
    "145.249.0.0/16",
    "176.14.0.0/15", "176.28.0.0/16", "176.32.0.0/14", "176.49.0.0/16",
    "176.51.0.0/16", "176.52.0.0/14", "176.59.0.0/16", "176.96.0.0/16",
    "176.97.0.0/16", "176.99.0.0/16", "176.100.0.0/16", "176.101.0.0/16",
    "176.106.0.0/16", "176.107.0.0/16", "176.109.0.0/16", "176.112.0.0/16",
    "176.113.0.0/16", "176.114.0.0/16", "176.116.0.0/16", "176.117.0.0/16",
    "176.118.0.0/16", "176.119.0.0/16", "176.120.0.0/16", "176.122.0.0/16",
    "176.124.0.0/14", "176.195.0.0/16", "176.196.0.0/14", "176.208.0.0/14",
    "176.212.0.0/14", "176.222.0.0/16", "176.226.0.0/15",
    "178.16.0.0/16", "178.20.0.0/16", "178.21.0.0/16", "178.22.0.0/16",
    "178.35.0.0/16", "178.36.0.0/16", "178.44.0.0/14", "178.46.0.0/15",
    "178.48.0.0/14", "178.57.0.0/16", "178.59.0.0/16", "178.62.0.0/16",
    "178.68.0.0/14", "178.72.0.0/16", "178.120.0.0/14", "178.124.0.0/14",
    "178.140.0.0/14", "178.154.128.0/17", "178.159.0.0/16",
    "178.162.0.0/16", "178.168.0.0/16", "178.172.0.0/14", "178.176.0.0/14",
    "178.204.0.0/14", "178.208.0.0/16", "178.209.0.0/16", "178.210.0.0/15",
    "178.212.0.0/16", "178.213.0.0/16", "178.214.0.0/16", "178.218.0.0/16",
    "178.237.0.0/16", "178.248.0.0/16", "178.249.0.0/16",
    "185.3.0.0/16", "185.4.0.0/16", "185.5.0.0/16", "185.6.0.0/16",
    "185.8.0.0/16", "185.12.0.0/16", "185.13.0.0/16", "185.14.0.0/16",
    "185.15.0.0/16", "185.16.0.0/16", "185.18.0.0/16", "185.22.0.0/16",
    "185.23.0.0/16", "185.25.0.0/16", "185.26.0.0/16", "185.29.0.0/16",
    "185.30.0.0/16", "185.31.0.0/16", "185.32.184.0/22",
    "185.36.0.0/16", "185.39.0.0/16", "185.41.0.0/16", "185.42.0.0/16",
    "185.43.0.0/16", "185.44.0.0/16", "185.46.0.0/16", "185.50.0.0/16",
    "185.54.0.0/16", "185.59.0.0/16", "185.63.0.0/16", "185.66.0.0/16",
    "185.68.0.0/16", "185.71.0.0/16", "185.71.76.0/22", "185.72.0.0/16",
    "185.76.0.0/16", "185.78.0.0/16", "185.86.0.0/16", "185.88.0.0/16",
    "185.91.0.0/16", "185.97.0.0/16", "185.99.0.0/16", "185.100.0.0/16",
    "185.101.0.0/16", "185.102.0.0/16", "185.103.0.0/16", "185.104.0.0/16",
    "185.105.0.0/16", "185.107.0.0/16", "185.112.0.0/16", "185.114.0.0/16",
    "185.117.0.0/16", "185.119.0.0/16", "185.120.0.0/16", "185.130.0.0/16",
    "185.141.0.0/16", "185.143.0.0/16", "185.145.0.0/16", "185.146.0.0/16",
    "185.148.0.0/16", "185.149.0.0/16", "185.154.0.0/16", "185.161.0.0/16",
    "185.163.0.0/16", "185.165.0.0/16", "185.168.0.0/16", "185.170.0.0/16",
    "185.173.0.0/16", "185.176.0.0/16", "185.178.0.0/16", "185.179.0.0/16",
    "185.180.0.0/16", "185.182.0.0/16", "185.185.0.0/16", "185.186.0.0/16",
    "185.188.0.0/16", "185.189.0.0/16", "185.193.0.0/16", "185.195.0.0/16",
    "185.198.0.0/16", "185.200.0.0/16", "185.201.0.0/16", "185.203.0.0/16",
    "185.204.0.0/16", "185.206.0.0/16", "185.209.0.0/16", "185.210.0.0/16",
    "185.212.0.0/16", "185.215.0.0/16", "185.217.0.0/16", "185.219.0.0/16",
    "185.220.0.0/16", "185.221.0.0/16", "185.222.0.0/16", "185.223.0.0/16",
    "185.225.0.0/16", "185.228.0.0/16", "185.230.0.0/16", "185.231.0.0/16",
    "185.233.0.0/16", "185.237.0.0/16", "185.240.0.0/16", "185.241.0.0/16",
    "185.242.0.0/16", "185.243.0.0/16", "185.244.0.0/16", "185.245.0.0/16",
    "185.246.0.0/16", "185.248.0.0/16", "185.250.0.0/16", "185.251.0.0/16",
    "185.253.0.0/16", "185.254.0.0/16",
    "188.16.0.0/14", "188.32.0.0/12", "188.64.0.0/16", "188.65.0.0/16",
    "188.93.0.0/16", "188.116.0.0/16", "188.120.0.0/14", "188.128.0.0/12",
    "188.162.0.0/15", "188.168.0.0/13", "188.186.0.0/15", "188.226.0.0/16",
    "188.227.0.0/16", "188.233.0.0/16", "188.234.0.0/15", "188.242.0.0/15",
    "188.244.0.0/14",
    "193.0.0.0/16", "193.3.0.0/16", "193.19.0.0/16", "193.22.0.0/16",
    "193.23.0.0/16", "193.24.0.0/16", "193.25.0.0/16", "193.26.0.0/16",
    "193.28.0.0/16", "193.29.0.0/16", "193.32.0.0/16", "193.33.0.0/16",
    "193.34.0.0/16", "193.36.0.0/16", "193.37.0.0/16", "193.38.0.0/16",
    "193.41.0.0/16", "193.42.0.0/16", "193.43.0.0/16", "193.46.0.0/16",
    "193.47.0.0/16", "193.56.0.0/16", "193.104.0.0/14", "193.124.0.0/14",
    "193.150.0.0/16", "193.164.0.0/16", "193.168.0.0/16", "193.176.0.0/16",
    "193.178.0.0/16", "193.180.0.0/16", "193.186.0.0/16", "193.200.0.0/16",
    "193.222.0.0/16", "193.224.0.0/14", "193.228.0.0/16", "193.232.0.0/14",
    "193.238.0.0/16",
    "194.8.0.0/16", "194.24.0.0/16", "194.26.0.0/16", "194.28.0.0/16",
    "194.32.0.0/16", "194.44.0.0/16", "194.48.0.0/16", "194.50.0.0/16",
    "194.54.0.0/16", "194.58.0.0/16", "194.60.0.0/16", "194.67.0.0/16",
    "194.79.0.0/16", "194.84.0.0/16", "194.85.0.0/16", "194.87.0.0/16",
    "194.105.0.0/16", "194.110.0.0/16", "194.135.0.0/16", "194.140.0.0/16",
    "194.145.0.0/16", "194.147.0.0/16", "194.150.0.0/16", "194.152.0.0/16",
    "194.154.0.0/16", "194.158.0.0/16", "194.165.0.0/16", "194.186.0.0/15",
    "194.190.0.0/15",
    "195.2.0.0/16", "195.3.0.0/16", "195.5.0.0/16", "195.9.0.0/16",
    "195.12.0.0/16", "195.16.0.0/16", "195.18.0.0/16", "195.19.0.0/16",
    "195.20.0.0/16", "195.34.0.0/16", "195.38.0.0/16", "195.42.0.0/16",
    "195.46.0.0/16", "195.54.0.0/16", "195.58.0.0/16", "195.62.0.0/16",
    "195.64.0.0/16", "195.68.0.0/16", "195.69.0.0/16", "195.70.0.0/16",
    "195.72.0.0/16", "195.80.0.0/16", "195.82.0.0/16", "195.85.0.0/16",
    "195.88.0.0/16", "195.91.0.0/16", "195.93.0.0/16", "195.98.0.0/16",
    "195.128.0.0/16", "195.131.0.0/16", "195.133.0.0/16", "195.140.0.0/16",
    "195.146.0.0/16", "195.149.0.0/16", "195.151.0.0/16", "195.152.0.0/16",
    "195.158.0.0/16", "195.161.0.0/16", "195.162.0.0/16", "195.170.0.0/16",
    "195.178.0.0/16", "195.182.0.0/16", "195.189.0.0/16", "195.190.0.0/16",
    "195.200.0.0/16", "195.208.0.0/14", "195.214.0.0/16", "195.216.0.0/16",
    "195.218.0.0/16", "195.222.0.0/16", "195.226.0.0/16", "195.230.0.0/16",
    "195.234.0.0/16", "195.239.0.0/16", "195.242.0.0/16", "195.245.0.0/16",
    "195.248.0.0/16", "195.250.0.0/16",
    "212.1.0.0/16", "212.3.0.0/16", "212.5.0.0/16", "212.8.0.0/16",
    "212.12.0.0/16", "212.15.0.0/16", "212.17.0.0/16", "212.19.0.0/16",
    "212.20.0.0/16", "212.22.0.0/16", "212.23.0.0/16", "212.24.0.0/16",
    "212.32.0.0/16", "212.34.0.0/16", "212.41.0.0/16", "212.42.0.0/16",
    "212.45.0.0/16", "212.46.0.0/16", "212.48.0.0/16", "212.49.0.0/16",
    "212.57.0.0/16", "212.59.0.0/16", "212.75.0.0/16", "212.90.0.0/16",
    "212.92.0.0/16", "212.93.0.0/16", "212.96.0.0/16", "212.100.0.0/16",
    "212.109.0.0/16", "212.110.0.0/16", "212.116.0.0/16", "212.119.0.0/16",
    "212.120.0.0/16", "212.122.0.0/16", "212.124.0.0/16", "212.152.0.0/16",
    "212.164.0.0/14", "212.176.0.0/16", "212.192.0.0/14", "212.220.0.0/16",
    "212.233.0.0/16", "212.248.0.0/16",
    "213.5.0.0/16", "213.24.0.0/14", "213.33.0.0/16", "213.59.0.0/16",
    "213.79.0.0/16", "213.80.0.0/16", "213.85.0.0/16", "213.87.0.0/16",
    "213.108.0.0/16", "213.131.0.0/16", "213.138.0.0/16", "213.148.0.0/16",
    "213.166.0.0/16", "213.167.0.0/16", "213.170.0.0/16", "213.171.0.0/16",
    "213.177.0.0/16", "213.178.0.0/16", "213.180.0.0/16", "213.180.192.0/19",
    "213.182.0.0/16", "213.186.0.0/16", "213.189.0.0/16", "213.219.0.0/16",
    "213.222.0.0/16", "213.228.0.0/16", "213.232.0.0/16", "213.234.0.0/16",
    "217.12.0.0/16", "217.15.0.0/16", "217.16.0.0/16", "217.18.0.0/16",
    "217.23.0.0/16", "217.24.0.0/16", "217.25.0.0/16", "217.28.0.0/16",
    "217.29.0.0/16", "217.65.0.0/16", "217.66.0.0/16", "217.67.0.0/16",
    "217.69.0.0/16", "217.70.0.0/16", "217.73.0.0/16", "217.74.0.0/16",
    "217.76.0.0/16", "217.106.0.0/16", "217.107.0.0/16", "217.112.0.0/16",
    "217.114.0.0/16", "217.116.0.0/16", "217.117.0.0/16", "217.118.0.0/16",
    "217.119.0.0/16", "217.145.0.0/16", "217.148.0.0/16", "217.150.0.0/16",
    "217.170.0.0/16", "217.172.0.0/16", "217.174.0.0/16", "217.195.0.0/16",
    "217.196.0.0/16", "217.197.0.0/16", "217.198.0.0/16",
];

// ═══════════════════════════════════════════════════════════════════
// СТРУКТУРЫ
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct VlessConfig {
    raw_uri: String,
    address: String,
    port: u16,
    params: IndexMap<String, String>,
    resolved_ip: Option<IpAddr>,
}

#[derive(Debug, Clone)]
struct TestResult {
    config: VlessConfig,
    tcp_ping_min_ms: f64,
    tcp_ping_avg_ms: f64,
    real_latency_ms: f64,
    download_bytes: u64,
    download_time_ms: f64,
    passed: bool,
}

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

// Глобальный счётчик портов для SOCKS-прокси
static PORT_COUNTER: AtomicUsize = AtomicUsize::new(0);

// ═══════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    let start_time = Instant::now();
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  VPN Parser v2 — Real xray-core testing                    ║");
    info!("║  VLESS + XHTTP + XTLS Reality + CIDR/SNI RU               ║");
    info!("╚══════════════════════════════════════════════════════════════╝");

    let stats = Arc::new(Stats::new());

    // Шаг 0: Установка xray-core
    info!("━━━ Шаг 0: Установка xray-core ━━━");
    install_xray().await?;

    // Шаг 1: RU CIDR
    info!("━━━ Шаг 1: Загрузка RU CIDR блоков ━━━");
    let ru_cidrs = load_ru_cidrs()?;
    info!("  Загружено {} RU CIDR блоков", ru_cidrs.len());

    // Шаг 2: Источники
    info!("━━━ Шаг 2: Загрузка из {} источников ━━━", SOURCES.len());
    let raw_configs = fetch_all_sources(Arc::clone(&stats)).await;
    info!("  Загружено {} строк", stats.total_fetched.load(Ordering::Relaxed));

    // Шаг 3: Парсинг
    info!("━━━ Шаг 3: Парсинг VLESS URI ━━━");
    let vless_configs = parse_vless_configs(&raw_configs, Arc::clone(&stats));
    info!("  Распарсено {} VLESS", stats.total_vless.load(Ordering::Relaxed));

    // Шаг 4: Фильтрация
    info!("━━━ Шаг 4: Фильтрация (XHTTP + Reality + RU) ━━━");
    let filtered = filter_configs(vless_configs, &ru_cidrs, Arc::clone(&stats)).await;
    info!("  После фильтрации: {}", filtered.len());

    if filtered.is_empty() {
        warn!("Не найдено подходящих конфигураций.");
        write_empty_output()?;
        return Ok(());
    }

    // Шаг 5: Реальное тестирование через xray-core
    info!("━━━ Шаг 5: Тестирование {} конфигов через xray-core ━━━", filtered.len());
    let results = test_all_via_xray(filtered, Arc::clone(&stats)).await;
    info!(
        "  Протестировано: {}, Прошло: {}",
        stats.total_tested.load(Ordering::Relaxed),
        stats.total_passed.load(Ordering::Relaxed)
    );

    // Шаг 6: Сортировка и вывод
    info!("━━━ Шаг 6: Сортировка и вывод ━━━");
    let final_results = sort_and_limit(results);
    write_output(&final_results)?;

    let elapsed = start_time.elapsed();
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  ЗАВЕРШЕНО за {:.1} сек", elapsed.as_secs_f64());
    info!("║  Найдено {} рабочих серверов", final_results.len());
    info!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// УСТАНОВКА XRAY-CORE
// ═══════════════════════════════════════════════════════════════════

async fn install_xray() -> Result<()> {
    // Проверяем, есть ли уже xray
    if let Ok(output) = Command::new("./xray").arg("version").output().await {
        if output.status.success() {
            let ver = String::from_utf8_lossy(&output.stdout);
            info!("  xray уже установлен: {}", ver.lines().next().unwrap_or(""));
            return Ok(());
        }
    }

    info!("  Скачивание xray-core...");

    let output = Command::new("bash")
        .arg("-c")
        .arg(r#"
            set -e
            XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+' || echo "25.1.30")
            echo "Downloading xray v${XRAY_VERSION}..."
            curl -sL "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" -o xray.zip
            unzip -o xray.zip xray -d .
            chmod +x ./xray
            rm -f xray.zip
            ./xray version | head -1
        "#)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Не удалось установить xray-core")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Ошибка установки xray: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    info!("  xray установлен: {}", stdout.trim());
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// ГЕНЕРАЦИЯ XRAY-КОНФИГА ДЛЯ ТЕСТИРОВАНИЯ
// ═══════════════════════════════════════════════════════════════════

fn generate_xray_config(config: &VlessConfig, socks_port: u16) -> serde_json::Value {
    let uuid = config.raw_uri
        .strip_prefix("vless://")
        .and_then(|s| s.split('@').next())
        .unwrap_or("");

    let security = config.params.get("security").cloned().unwrap_or_default();
    let sni = config.params.get("sni").cloned().unwrap_or_default();
    let fp = config.params.get("fp").cloned().unwrap_or_else(|| "chrome".to_string());
    let pbk = config.params.get("pbk").cloned().unwrap_or_default();
    let sid = config.params.get("sid").cloned().unwrap_or_default();
    let spx = config.params.get("spx").cloned().unwrap_or_else(|| "/".to_string());
    let flow = config.params.get("flow").cloned().unwrap_or_default();

    let net_type = config.params.get("type").cloned().unwrap_or_else(|| "xhttp".to_string());
    let path = config.params.get("path").cloned().unwrap_or_else(|| "/".to_string());
    let host = config.params.get("host").cloned().unwrap_or_default();
    let mode = config.params.get("mode").cloned().unwrap_or_else(|| "auto".to_string());
    let extra = config.params.get("extra").cloned().unwrap_or_default();

    let mut stream_settings = serde_json::json!({
        "network": net_type,
        "security": security,
    });

    // xhttpSettings
    let mut xhttp_settings = serde_json::json!({
        "path": path,
        "mode": mode,
    });
    if !host.is_empty() {
        xhttp_settings["host"] = serde_json::json!(host);
    }
    if !extra.is_empty() {
        if let Ok(extra_val) = serde_json::from_str::<serde_json::Value>(&extra) {
            xhttp_settings["extra"] = extra_val;
        }
    }

    // Xray использует "xhttpSettings" для xhttp/splithttp
    let settings_key = if net_type == "splithttp" {
        "splithttpSettings"
    } else {
        "xhttpSettings"
    };
    stream_settings[settings_key] = xhttp_settings;

    // Reality settings
    if security == "reality" {
        stream_settings["realitySettings"] = serde_json::json!({
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": pbk,
            "shortId": sid,
            "spiderX": spx,
        });
    }

    let mut vnext_user = serde_json::json!({
        "id": uuid,
        "encryption": "none",
    });
    if !flow.is_empty() {
        vnext_user["flow"] = serde_json::json!(flow);
    }

    serde_json::json!({
        "log": {
            "loglevel": "none"
        },
        "inbounds": [{
            "tag": "socks-in",
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "udp": false
            }
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": config.address,
                    "port": config.port,
                    "users": [vnext_user]
                }]
            },
            "streamSettings": stream_settings
        }]
    })
}

// ═══════════════════════════════════════════════════════════════════
// РЕАЛЬНОЕ ТЕСТИРОВАНИЕ ЧЕРЕЗ XRAY-CORE
// ═══════════════════════════════════════════════════════════════════

async fn test_all_via_xray(
    configs: Vec<VlessConfig>,
    stats: Arc<Stats>,
) -> Vec<TestResult> {
    // Сначала быстро отсеиваем мёртвые серверы через TCP ping
    info!("  Предварительный TCP ping...");
    let alive_configs: Vec<(VlessConfig, f64, f64)> = stream::iter(configs)
        .filter_map(|config| async move {
            match tcp_ping(&config).await {
                Some((avg, min)) => {
                    debug!("  ✓ TCP {}:{} — {:.0}ms", config.address, config.port, min);
                    Some((config, avg, min))
                }
                None => {
                    debug!("  ✗ TCP {}:{} — DEAD", config.address, config.port);
                    None
                }
            }
        })
        .buffer_unordered(CONCURRENT_TESTS * 2)
        .collect()
        .await;

    info!("  TCP-живых: {} из общего числа", alive_configs.len());

    // Теперь тестируем живые через xray
    let results: Vec<TestResult> = stream::iter(alive_configs)
        .map(|(config, tcp_avg, tcp_min)| {
            let stats = Arc::clone(&stats);
            async move {
                stats.total_tested.fetch_add(1, Ordering::Relaxed);
                let tested = stats.total_tested.load(Ordering::Relaxed);

                let result = test_single_via_xray(config, tcp_avg, tcp_min).await;

                if result.passed {
                    stats.total_passed.fetch_add(1, Ordering::Relaxed);
                    info!(
                        "  ✓ [{}/{}] {}:{} — latency: {:.0}ms, download: {} bytes",
                        tested,
                        alive_configs.len(),
                        result.config.address,
                        result.config.port,
                        result.real_latency_ms,
                        result.download_bytes,
                    );
                } else {
                    debug!(
                        "  ✗ [{}/{}] {}:{} — FAILED",
                        tested,
                        alive_configs.len(),
                        result.config.address,
                        result.config.port,
                    );
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

async fn test_single_via_xray(
    config: VlessConfig,
    tcp_avg: f64,
    tcp_min: f64,
) -> TestResult {
    let mut result = TestResult {
        config: config.clone(),
        tcp_ping_min_ms: tcp_min,
        tcp_ping_avg_ms: tcp_avg,
        real_latency_ms: f64::MAX,
        download_bytes: 0,
        download_time_ms: 0.0,
        passed: false,
    };

    // Уникальный порт для этого теста
    let port_offset = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let socks_port = SOCKS_PORT_BASE + (port_offset as u16 % 10000);

    // Генерируем конфиг xray
    let xray_config = generate_xray_config(&config, socks_port);
    let config_path = format!("/tmp/xray_test_{}.json", socks_port);

    // Записываем конфиг
    if let Err(e) = tokio::fs::write(&config_path, xray_config.to_string()).await {
        debug!("  Не удалось записать конфиг: {}", e);
        return result;
    }

    // Запускаем xray
    let mut xray_process = match Command::new("./xray")
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(p) => p,
        Err(e) => {
            debug!("  Не удалось запустить xray: {}", e);
            let _ = tokio::fs::remove_file(&config_path).await;
            return result;
        }
    };

    // Ждём запуска
    tokio::time::sleep(XRAY_STARTUP_WAIT).await;

    // Проверяем что SOCKS порт открылся
    let socks_alive = timeout(
        Duration::from_secs(2),
        TcpStream::connect(format!("127.0.0.1:{}", socks_port)),
    )
    .await;

    if socks_alive.is_err() || socks_alive.unwrap().is_err() {
        debug!("  SOCKS5 порт {} не открылся", socks_port);
        let _ = xray_process.kill().await;
        let _ = tokio::fs::remove_file(&config_path).await;
        return result;
    }

    // URL Test — реальный HTTP-запрос через SOCKS5
    let proxy_url = format!("socks5://127.0.0.1:{}", socks_port);

    let proxy = match reqwest::Proxy::all(&proxy_url) {
        Ok(p) => p,
        Err(_) => {
            let _ = xray_process.kill().await;
            let _ = tokio::fs::remove_file(&config_path).await;
            return result;
        }
    };

    let client = match reqwest::Client::builder()
        .proxy(proxy)
        .timeout(XRAY_TEST_TIMEOUT)
        .connect_timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .no_gzip()
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            let _ = xray_process.kill().await;
            let _ = tokio::fs::remove_file(&config_path).await;
            return result;
        }
    };

    // Тест 1: URL Test (проверка что трафик проходит)
    let mut url_test_passed = false;
    let mut best_latency = f64::MAX;

    for test_url in TEST_URLS {
        let start = Instant::now();
        match timeout(Duration::from_secs(12), client.get(*test_url).send()).await {
            Ok(Ok(resp)) => {
                let status = resp.status().as_u16();
                if status == 200 || status == 204 || status == 301 || status == 302 {
                    let latency = start.elapsed().as_secs_f64() * 1000.0;
                    if latency < best_latency {
                        best_latency = latency;
                    }
                    url_test_passed = true;
                    break;
                }
            }
            _ => continue,
        }
    }

    if !url_test_passed {
        let _ = xray_process.kill().await;
        let _ = tokio::fs::remove_file(&config_path).await;
        return result;
    }

    result.real_latency_ms = best_latency;

    // Тест 2: Speed test (скачивание 500KB)
    let speed_start = Instant::now();
    match timeout(Duration::from_secs(15), client.get(SPEED_TEST_URL).send()).await {
        Ok(Ok(resp)) => {
            if resp.status().is_success() {
                match timeout(Duration::from_secs(10), resp.bytes()).await {
                    Ok(Ok(body)) => {
                        result.download_bytes = body.len() as u64;
                        result.download_time_ms = speed_start.elapsed().as_secs_f64() * 1000.0;
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    result.passed = true;

    // Убиваем xray
    let _ = xray_process.kill().await;
    let _ = tokio::fs::remove_file(&config_path).await;

    result
}

// ═══════════════════════════════════════════════════════════════════
// TCP PING
// ═══════════════════════════════════════════════════════════════════

async fn tcp_ping(config: &VlessConfig) -> Option<(f64, f64)> {
    let addr = resolve_to_socket_addr(&config.address, config.port).await?;
    let mut times = Vec::with_capacity(TCP_PING_ROUNDS);

    for _ in 0..TCP_PING_ROUNDS {
        let start = Instant::now();
        match timeout(TCP_PING_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                times.push(start.elapsed().as_secs_f64() * 1000.0);
                drop(stream);
            }
            _ => continue,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    if times.is_empty() {
        return None;
    }

    let avg = times.iter().sum::<f64>() / times.len() as f64;
    let min = times.iter().cloned().fold(f64::MAX, f64::min);
    Some((avg, min))
}

async fn resolve_to_socket_addr(address: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    let addr_str = format!("{}:{}", address, port);
    match tokio::task::spawn_blocking(move || addr_str.to_socket_addrs()).await {
        Ok(Ok(mut addrs)) => addrs.next(),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════
// CIDR / SNI
// ═══════════════════════════════════════════════════════════════════

fn load_ru_cidrs() -> Result<Vec<IpNetwork>> {
    let mut cidrs = Vec::with_capacity(RU_CIDRS.len());
    for s in RU_CIDRS {
        if let Ok(net) = s.parse::<IpNetwork>() {
            cidrs.push(net);
        }
    }
    Ok(cidrs)
}

fn is_ip_in_ru_cidrs(ip: IpAddr, cidrs: &[IpNetwork]) -> bool {
    cidrs.iter().any(|c| c.contains(ip))
}

fn is_ru_sni(sni: &str) -> bool {
    let s = sni.to_lowercase();
    s.ends_with(".ru") || s.ends_with(".su")
        || s == "ru" || s == "su"
        || s.contains("yandex.ru") || s.contains("mail.ru")
        || s.contains("vk.com") || s.contains("gosuslugi")
        || s.contains("mos.ru") || s.contains("x5.ru")
        || s.contains("tinkoff.ru") || s.contains("avito")
        || s.contains("userapi.com") || s.contains("oneme.ru")
}

// ═══════════════════════════════════════════════════════════════════
// ЗАГРУЗКА ИСТОЧНИКОВ
// ═══════════════════════════════════════════════════════════════════

async fn fetch_all_sources(stats: Arc<Stats>) -> Vec<String> {
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0")
        .build()
        .expect("HTTP client");

    let all_lines: Arc<DashMap<String, ()>> = Arc::new(DashMap::new());

    let _: Vec<()> = stream::iter(SOURCES.iter().enumerate())
        .map(|(idx, url)| {
            let client = client.clone();
            let all_lines = Arc::clone(&all_lines);
            let stats = Arc::clone(&stats);
            async move {
                match fetch_single(&client, url).await {
                    Ok(lines) => {
                        let count = lines.len();
                        for l in lines { all_lines.insert(l, ()); }
                        stats.total_fetched.fetch_add(count, Ordering::Relaxed);
                        info!("  [{}/{}] ✓ {} строк", idx + 1, SOURCES.len(), count);
                    }
                    Err(e) => {
                        warn!("  [{}/{}] ✗ {}", idx + 1, SOURCES.len(), e);
                    }
                }
            }
        })
        .buffer_unordered(CONCURRENT_FETCHES)
        .collect()
        .await;

    all_lines.iter().map(|e| e.key().clone()).collect()
}

async fn fetch_single(client: &reqwest::Client, url: &str) -> Result<Vec<String>> {
    let resp = client.get(url).send().await.context("HTTP error")?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {}", resp.status());
    }
    let body = resp.text().await.context("read body")?;
    let decoded = try_decode_base64(&body);
    let text = decoded.as_deref().unwrap_or(&body);
    Ok(text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
}

fn try_decode_base64(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.contains("vless://") || trimmed.contains("vmess://") {
        return None;
    }
    let engines = [&STANDARD, &URL_SAFE, &URL_SAFE_NO_PAD];
    for engine in &engines {
        if let Ok(bytes) = engine.decode(trimmed.as_bytes()) {
            if let Ok(decoded) = String::from_utf8(bytes) {
                if decoded.contains("vless://") { return Some(decoded); }
            }
        }
    }
    let mut lines = Vec::new();
    let mut any = false;
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let mut done = false;
        for engine in &engines {
            if let Ok(b) = engine.decode(line.as_bytes()) {
                if let Ok(d) = String::from_utf8(b) {
                    if d.contains("://") { lines.push(d); any = true; done = true; break; }
                }
            }
        }
        if !done { lines.push(line.to_string()); }
    }
    if any { Some(lines.join("\n")) } else { None }
}

// ═══════════════════════════════════════════════════════════════════
// ПАРСИНГ VLESS
// ═══════════════════════════════════════════════════════════════════

fn parse_vless_configs(raw: &[String], stats: Arc<Stats>) -> Vec<VlessConfig> {
    let seen: DashMap<String, ()> = DashMap::new();
    let configs: Vec<VlessConfig> = raw.iter()
        .filter_map(|l| {
            let l = l.trim();
            if !l.starts_with("vless://") { return None; }
            parse_single_vless(l, &seen)
        })
        .collect();
    stats.total_vless.store(configs.len(), Ordering::Relaxed);
    configs
}

fn parse_single_vless(uri: &str, seen: &DashMap<String, ()>) -> Option<VlessConfig> {
    let without = uri.strip_prefix("vless://")?;
    let (main_part, _remark) = match without.split_once('#') {
        Some((m, r)) => (m, r),
        None => (without, ""),
    };
    let (auth_part, query) = match main_part.split_once('?') {
        Some((a, q)) => (a, q),
        None => (main_part, ""),
    };
    let (_uuid, host_port) = auth_part.split_once('@')?;
    let (address, port) = parse_host_port(host_port)?;
    let params = parse_query(query);

    // Дедупликация по hash
    let hash_input = format!("{}|{}|{}|{}|{}",
        _uuid, address, port,
        params.get("type").unwrap_or(&String::new()),
        params.get("sni").unwrap_or(&String::new()),
    );
    let mut h = Sha256::new();
    h.update(hash_input.as_bytes());
    let hash = hex::encode(h.finalize());
    if seen.contains_key(&hash) { return None; }
    seen.insert(hash, ());

    Some(VlessConfig {
        raw_uri: uri.to_string(),
        address,
        port,
        params,
        resolved_ip: None,
    })
}

fn parse_host_port(input: &str) -> Option<(String, u16)> {
    if input.starts_with('[') {
        let end = input.find(']')?;
        let addr = input[1..end].to_string();
        let port: u16 = input.get(end + 2..)?.parse().ok()?;
        Some((addr, port))
    } else {
        let i = input.rfind(':')?;
        let addr = input[..i].to_string();
        let port: u16 = input[i + 1..].parse().ok()?;
        if addr.is_empty() || port == 0 { return None; }
        Some((addr, port))
    }
}

fn parse_query(q: &str) -> IndexMap<String, String> {
    let mut m = IndexMap::new();
    if q.is_empty() { return m; }
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            m.insert(
                percent_decode_str(k).decode_utf8_lossy().to_lowercase(),
                percent_decode_str(v).decode_utf8_lossy().to_string(),
            );
        }
    }
    m
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
                let t = config.params.get("type").map(|s| s.to_lowercase());
                if !matches!(t.as_deref(), Some("xhttp") | Some("splithttp")) { return None; }

                let sec = config.params.get("security").map(|s| s.to_lowercase());
                if !matches!(sec.as_deref(), Some("reality")) { return None; }

                if !config.params.get("pbk").map(|s| !s.is_empty()).unwrap_or(false) { return None; }

                let sni = config.params.get("sni").cloned().unwrap_or_default();
                let server_name = config.params.get("servername").cloned().unwrap_or_default();
                let effective_sni = if !sni.is_empty() { sni } else { server_name };
                let sni_ru = is_ru_sni(&effective_sni);

                let resolved = resolve_address(&config.address).await;
                config.resolved_ip = resolved;
                let ip_ru = config.resolved_ip.map(|ip| is_ip_in_ru_cidrs(ip, &cidrs)).unwrap_or(false);

                if !sni_ru && !ip_ru { return None; }

                Some(config)
            }
        })
        .collect()
        .await;

    stats.total_filtered.store(filtered.len(), Ordering::Relaxed);
    filtered
}

async fn resolve_address(address: &str) -> Option<IpAddr> {
    if let Ok(ip) = address.parse::<IpAddr>() { return Some(ip); }
    let a = format!("{}:0", address);
    match tokio::task::spawn_blocking(move || a.to_socket_addrs()).await {
        Ok(Ok(mut addrs)) => addrs.next().map(|sa| sa.ip()),
        _ => {
            let resolver = trust_dns_resolver::TokioAsyncResolver::tokio(
                trust_dns_resolver::config::ResolverConfig::google(),
                trust_dns_resolver::config::ResolverOpts::default(),
            );
            resolver.lookup_ip(address).await.ok()?.iter().next()
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// СОРТИРОВКА И ВЫВОД
// ═══════════════════════════════════════════════════════════════════

fn sort_and_limit(mut results: Vec<TestResult>) -> Vec<TestResult> {
    // Сортируем по реальной задержке (через прокси)
    results.sort_by(|a, b| {
        a.real_latency_ms.partial_cmp(&b.real_latency_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results.truncate(MAX_KEYS);
    results
}

fn write_output(results: &[TestResult]) -> Result<()> {
    use std::io::Write;
    let mut out = String::new();

    out.push_str("# VPN Parser v2 — Best RU CIDR + XHTTP + Reality Keys\n");
    out.push_str(&format!("# Generated: {}\n", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    out.push_str(&format!("# Total working keys: {}\n", results.len()));
    out.push_str("# Filter: VLESS + XHTTP + XTLS Reality + CIDR/SNI RU\n");
    out.push_str("# Tested: Real traffic through xray-core SOCKS5 proxy\n");
    out.push_str("# Sorted by: real proxy latency (URL test through xray)\n");
    out.push_str("#\n");
    out.push_str(&format!(
        "# {:>3} | {:>8} | {:>10} | {:>10} | {:>12} | {}\n",
        "#", "TCP(ms)", "Real(ms)", "Down(KB)", "Speed(KB/s)", "Server"
    ));
    out.push_str(&format!("# {}\n", "─".repeat(80)));

    for (i, r) in results.iter().enumerate() {
        let speed_kbs = if r.download_time_ms > 0.0 {
            (r.download_bytes as f64 / 1024.0) / (r.download_time_ms / 1000.0)
        } else {
            0.0
        };
        out.push_str(&format!(
            "# {:>3} | {:>8.1} | {:>10.1} | {:>10} | {:>12.1} | {}:{}\n",
            i + 1,
            r.tcp_ping_min_ms,
            r.real_latency_ms,
            r.download_bytes / 1024,
            speed_kbs,
            r.config.address,
            r.config.port,
        ));
    }

    out.push_str("#\n# ═══════════════════ WORKING KEYS ═══════════════════\n#\n");

    for r in results {
        out.push_str(&r.config.raw_uri);
        out.push('\n');
    }

    let mut f = std::fs::File::create(OUTPUT_FILE).context("create file")?;
    f.write_all(out.as_bytes()).context("write file")?;
    info!("  Записано {} ключей в {}", results.len(), OUTPUT_FILE);
    Ok(())
}

fn write_empty_output() -> Result<()> {
    use std::io::Write;
    let out = format!(
        "# VPN Parser v2 — No working keys found\n# Generated: {}\n# All tested keys failed real traffic test.\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    let mut f = std::fs::File::create(OUTPUT_FILE)?;
    f.write_all(out.as_bytes())?;
    Ok(())
}
