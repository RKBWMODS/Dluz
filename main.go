package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

var (
	attackStats = struct {
		sync.RWMutex
		data map[string]interface{}
	}{data: make(map[string]interface{})}
	
	requestCounts = struct {
		sync.RWMutex
		ips map[string]int
	}{ips: make(map[string]int)}
)

func init() {
	// Initialize data structures
	attackStats.data = map[string]interface{}{
		"total_requests": 0,
		"blocked":        0,
		"bypass_attempts": 0,
		"proxy_ips":      make(map[string]bool),
		"start_time":     time.Now(),
		"target_url":     "https://example.com/api/vulnerable-endpoint",
	}
	
	// Start periodic cleanup
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			requestCounts.Lock()
			requestCounts.ips = make(map[string]int)
			requestCounts.Unlock()
		}
	}()
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Handle different routes
	switch r.URL.Path {
	case "/api/stats":
		getStats(w, r)
	case "/api/attack":
		logAttack(w, r)
	default:
		serveFrontend(w, r)
	}
}

func logAttack(w http.ResponseWriter, r *http.Request) {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}

	// Rate limiting
	requestCounts.Lock()
	requestCounts.ips[ip]++
	if requestCounts.ips[ip] > 30000 {
		attackStats.Lock()
		attackStats.data["blocked"] = attackStats.data["blocked"].(int) + 1
		attackStats.Unlock()
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "BLOCKED")
		return
	}
	requestCounts.Unlock()

	// Bypass detection
	if r.Header.Get("X-Bypass") == "true" {
		attackStats.Lock()
		attackStats.data["bypass_attempts"] = attackStats.data["bypass_attempts"].(int) + 1
		attackStats.Unlock()
	}

	// Proxy detection
	if r.Header.Get("Via") != "" || r.Header.Get("X-Proxy") != "" {
		attackStats.Lock()
		proxyIPs := attackStats.data["proxy_ips"].(map[string]bool)
		proxyIPs[ip] = true
		attackStats.data["proxy_ips"] = proxyIPs
		attackStats.Unlock()
	}

	// Update stats
	attackStats.Lock()
	attackStats.data["total_requests"] = attackStats.data["total_requests"].(int) + 1
	attackStats.Unlock()

	fmt.Fprint(w, "REQUEST_ACCEPTED")
}

func getStats(w http.ResponseWriter, r *http.Request) {
	attackStats.RLock()
	defer attackStats.RUnlock()
	
	// Calculate RPS
	duration := time.Since(attackStats.data["start_time"].(time.Time)).Seconds()
	rps := float64(attackStats.data["total_requests"].(int)) / duration
	
	// Prepare response
	stats := map[string]interface{}{
		"total_requests": attackStats.data["total_requests"],
		"blocked":        attackStats.data["blocked"],
		"bypass_attempts": attackStats.data["bypass_attempts"],
		"proxy_count":    len(attackStats.data["proxy_ips"].(map[string]bool)),
		"rps":           fmt.Sprintf("%.2f", rps),
		"target_url":    attackStats.data["target_url"],
		"uptime":        fmt.Sprintf("%.0fs", duration),
	}
	
	json.NewEncoder(w).Encode(stats)
}

func serveFrontend(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
