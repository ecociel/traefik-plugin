package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config holds the plugin configuration.
type Config struct {
	BlocklistPath string `json:"blocklistPath"`
}

// CreateConfig initializes the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		BlocklistPath: "/etc/traefik/blocklist.txt", // Default blocklist location
	}
}

// Fail2BanMiddleware is the plugin's main structure.
type Fail2BanMiddleware struct {
	next          http.Handler
	name          string
	blocklistPath string
	blockedIPs    map[string]struct{}
	mu            sync.RWMutex
}

// New creates a new Fail2BanMiddleware instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.BlocklistPath == "" {
		return nil, fmt.Errorf("blocklistPath cannot be empty")
	}

	middleware := &Fail2BanMiddleware{
		next:          next,
		name:          name,
		blocklistPath: config.BlocklistPath,
		blockedIPs:    make(map[string]struct{}),
	}

	// Load the initial blocklist
	err := middleware.reloadBlocklist()
	if err != nil {
		return nil, fmt.Errorf("failed to load blocklist: %w", err)
	}

	// Optionally, you can add a routine to watch for changes to the blocklist file.
	go middleware.watchBlocklistFile()

	return middleware, nil
}

// ServeHTTP implements the middleware logic.
func (m *Fail2BanMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := strings.Split(req.RemoteAddr, ":")[0]

	m.mu.RLock()
	_, blocked := m.blockedIPs[clientIP]
	m.mu.RUnlock()

	if blocked {
		http.Error(rw, "Forbidden: Your IP has been blocked", http.StatusForbidden)
		return
	}

	m.next.ServeHTTP(rw, req)
}

// reloadBlocklist reloads the blocklist from the file.
func (m *Fail2BanMiddleware) reloadBlocklist() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := ioutil.ReadFile(m.blocklistPath)
	if err != nil {
		return err
	}

	// Reset the map and reload it with new values.
	m.blockedIPs = make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		ip := strings.TrimSpace(line)
		if ip != "" {
			m.blockedIPs[ip] = struct{}{}
		}
	}

	return nil
}

// watchBlocklistFile watches for changes to the blocklist file.
func (m *Fail2BanMiddleware) watchBlocklistFile() {
	for {
		err := m.reloadBlocklist()
		if err != nil {
			fmt.Printf("Error reloading blocklist: %v\n", err)
		}
		// Reload every 30 seconds
		time.Sleep(30 * time.Second)
	}
}
