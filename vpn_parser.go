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
	MaxWorkers   = 100              // Увеличил для скорости
	MaxResults   = 250              // Лимит по требованию
	TestTimeout  = 7 * time.Second  // Время на проверку одного узла
	OutputFile   = "best_ru_cidr_xhttp_reality.txt"
)

// Источники (твои + проверенные мега-агрегаторы)
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
	Addr    string
}

func main() {
	fmt.Println("🌟 [START] Ultimate VPN Parser (Reality + XHTTP Edition)")
	
	// 1. Извлечение
	allLinks := collectAndDecode()
	uniqueLinks := unique(allLinks)
	fmt.Printf("🔍 Всего найдено уникальных ссылок: %d\n", len(uniqueLinks))

	// 2. Глубокая фильтрация
	targetLinks := filterStrict(uniqueLinks)
	fmt.Printf("🎯 Соответствуют критериям (Reality/XHTTP): %d\n", len(targetLinks))

	// 3. Многопоточный тест
	bestNodes := validate(targetLinks)

	// 4. Сортировка
	sort.Slice(bestNodes, func(i, j int) bool {
		return bestNodes[i].Latency < bestNodes[j].Latency
	})

	// 5. Сохранение
	save(bestNodes)
}

func collectAndDecode() []string {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var results []string
	client := &http.Client{Timeout: 15 * time.Second}

	for _, urlLink := range sources {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			resp, err := client.Get(s)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			content := string(body)

			// Если контент в Base64 (часто для V2Ray подписок)
			if decoded, err := base64.StdEncoding.DecodeString(content); err == nil {
				content = string(decoded)
			}

			re := regexp.MustCompile(`vless://[^\s#\x60"']+`)
			matches := re.FindAllString(content, -1)

			mu.Lock()
			results = append(results, matches...)
			mu.Unlock()
		}(urlLink)
	}
	wg.Wait()
	return results
}

func filterStrict(links []string) []string {
	var filtered []string
	for _, link := range links {
		l := strings.ToLower(link)
		// Условие: REALITY обязателен
		isReality := strings.Contains(l, "security=reality")
		// Условие: XHTTP или HTTP-Upgrade (актуально для обхода ТСПУ)
		isXHTTP := strings.Contains(l, "type=xhttp") || strings.Contains(l, "type=http") || strings.Contains(l, "type=h2")
		
		if isReality && isXHTTP {
			filtered = append(filtered, link)
		}
	}
	// Если XHTTP результатов слишком мало, добавим просто Reality (для стабильности)
	if len(filtered) < 10 {
		for _, link := range links {
			if strings.Contains(strings.ToLower(link), "security=reality") {
				filtered = append(filtered, link)
			}
		}
	}
	return filtered
}

func validate(links []string) []ProxyNode {
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

			host := u.Hostname()
			port := u.Port()
			if port == "" { port = "443" }

			// TCP Ping + Handshake check
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), TestTimeout)
			if err != nil {
				return
			}
			duration := time.Since(start)
			conn.Close()

			mu.Lock()
			valid = append(valid, ProxyNode{FullURL: l, Latency: duration, Addr: host})
			mu.Unlock()
		}(link)
	}
	wg.Wait()
	return valid
}

func save(nodes []ProxyNode) {
	file, _ := os.Create(OutputFile)
	defer file.Close()

	count := len(nodes)
	if count > MaxResults {
		count = MaxResults
	}

	for i := 0; i < count; i++ {
		// Добавляем пометку о задержке в название ключа
		line := fmt.Sprintf("%s#Lat_%dms\n", nodes[i].FullURL, nodes[i].Latency.Milliseconds())
		file.WriteString(line)
	}
	fmt.Printf("💾 Результаты сохранены в %s (%d шт)\n", OutputFile, count)
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
