package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// --- КОНФИГУРАЦИЯ ---
const (
	MaxWorkers   = 120              // Максимальная многопоточность
	MaxResults   = 250              // Лимит серверов в итоговом файле
	TestTimeout  = 5 * time.Second  // Быстрый таймаут для отсева медленных узлов
	OutputFile   = "best_ru_cidr_xhttp_reality.txt"
)

var sources = []string{
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
}

type ProxyNode struct {
	FullURL string
	Latency time.Duration
}

func main() {
	fmt.Println("🚀 СТАРТ: Поиск VLESS + XHTTP + Reality (Russia Optimized)")
	
	rawLinks := collectLinks()
	fmt.Printf("📦 Найдено ссылок: %d\n", len(rawLinks))

	filtered := filterRealityXHTTP(rawLinks)
	fmt.Printf("🎯 Соответствуют критериям: %d\n", len(filtered))

	validNodes := testNodes(filtered)
	
	sort.Slice(validNodes, func(i, j int) bool {
		return validNodes[i].Latency < validNodes[j].Latency
	})

	saveResults(validNodes)
}

func collectLinks() []string {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var results []string
	client := &http.Client{Timeout: 10 * time.Second}

	for _, s := range sources {
		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			resp, err := client.Get(urlStr)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			
			content := string(body)
			// Декодирование base64 если нужно
			if !strings.Contains(content, "vless://") {
				if dec, err := base64.StdEncoding.DecodeString(content); err == nil {
					content = string(dec)
				}
			}

			re := regexp.MustCompile(`vless://[^\s#\x60"']+`)
			matches := re.FindAllString(content, -1)
			
			mu.Lock()
			results = append(results, matches...)
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	return results
}

func filterRealityXHTTP(links []string) []string {
	var result []string
	set := make(map[string]struct{})

	for _, link := range links {
		l := strings.ToLower(link)
		// Фильтр: Reality ОБЯЗАТЕЛЬНО + XHTTP/HTTP (для обхода замедлений ТСПУ)
		if strings.Contains(l, "security=reality") {
			// Проверяем на XHTTP или наличие RU SNI
			isXHTTP := strings.Contains(l, "type=xhttp") || strings.Contains(l, "type=http")
			isRUSNI := strings.Contains(l, ".ru") || strings.Contains(l, "vk.com") || strings.Contains(l, "yandex")

			if isXHTTP || isRUSNI {
				if _, ok := set[link]; !ok {
					set[link] = struct{}{}
					result = append(result, link)
				}
			}
		}
	}
	return result
}

func testNodes(links []string) []ProxyNode {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var valid []ProxyNode
	sem := make(chan struct{}, MaxWorkers)

	for _, link := range links {
		wg.Add(1)
		sem <- struct{}{}
		go func(l string) {
			defer wg.Done()
			defer func() { <-sem }()

			u, err := url.Parse(l)
			if err != nil {
				return
			}

			addr := net.JoinHostPort(u.Hostname(), u.Port())
			if u.Port() == "" { addr = u.Hostname() + ":443" }

			start := time.Now()
			// TCP Ping (Handshake check)
			conn, err := net.DialTimeout("tcp", addr, TestTimeout)
			if err != nil {
				return
			}
			latency := time.Since(start)
			conn.Close()

			mu.Lock()
			valid = append(valid, ProxyNode{FullURL: l, Latency: latency})
			mu.Unlock()
		}(link)
	}
	wg.Wait()
	return valid
}

func saveResults(nodes []ProxyNode) {
	f, err := os.Create(OutputFile)
	if err != nil {
		return
	}
	defer f.Close()

	// Используем bufio для эффективной записи
	writer := bufio.NewWriter(f)
	
	limit := len(nodes)
	if limit > MaxResults {
		limit = MaxResults
	}

	for i := 0; i < limit; i++ {
		// Форматируем вывод: Ссылка + Комментарий с пингом
		entry := fmt.Sprintf("%s#Lat_%dms\n", nodes[i].FullURL, nodes[i].Latency.Milliseconds())
		writer.WriteString(entry)
	}
	writer.Flush()
	fmt.Printf("✅ Успешно сохранено %d узлов в %s\n", limit, OutputFile)
}
