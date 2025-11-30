package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	npmRegistry    = "https://registry.npmjs.org"
	goProxyURL     = "https://proxy.golang.org"
	dockerRegistry = "https://registry-1.docker.io"
	cacheDir       = "./cache"
	npmPort        = ":8080"
	goPort         = ":8081"
	ociPort        = ":8082"
)

type ProxyType string

const (
	NPMProxy ProxyType = "npm"
	GoProxy  ProxyType = "go"
	OCIProxy ProxyType = "oci"
)

type ProxyServer struct {
	proxyType   ProxyType
	cacheDir    string
	upstreamURL string
	client      *http.Client
}

func NewProxyServer(proxyType ProxyType, cacheDir, upstreamURL string) *ProxyServer {
	return &ProxyServer{
		proxyType:   proxyType,
		cacheDir:    cacheDir,
		upstreamURL: upstreamURL,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (p *ProxyServer) ensureCacheDir() error {
	return os.MkdirAll(p.cacheDir, 0755)
}

func (p *ProxyServer) getCachePath(requestPath string) string {
	cleanPath := strings.TrimPrefix(requestPath, "/")
	subDir := string(p.proxyType)
	return filepath.Join(p.cacheDir, subDir, cleanPath)
}

func (p *ProxyServer) isCached(cachePath string) bool {
	info, err := os.Stat(cachePath)
	if err != nil {
		return false
	}

	var maxAge time.Duration
	switch p.proxyType {
	case NPMProxy:
		if strings.HasSuffix(cachePath, ".tgz") {
			maxAge = 24 * time.Hour
		} else {
			maxAge = 1 * time.Hour
		}
	case GoProxy:
		// Go modules are immutable once published
		if strings.Contains(cachePath, "/@v/") {
			maxAge = 168 * time.Hour // 7 days
		} else {
			maxAge = 1 * time.Hour
		}
	case OCIProxy:
		// Container layers are immutable by digest
		if strings.Contains(cachePath, "/blobs/") {
			maxAge = 168 * time.Hour // 7 days
		} else {
			maxAge = 1 * time.Hour
		}
	default:
		maxAge = 1 * time.Hour
	}

	return time.Since(info.ModTime()) < maxAge
}

func (p *ProxyServer) fetchFromUpstream(requestPath string, headers http.Header) ([]byte, http.Header, int, error) {
	url := p.upstreamURL + requestPath
	log.Printf("[%s] Fetching: %s", p.proxyType, url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Forward important headers for OCI registry auth
	if p.proxyType == OCIProxy {
		if auth := headers.Get("Authorization"); auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if accept := headers.Get("Accept"); accept != "" {
			req.Header.Set("Accept", accept)
		} else {
			// Default OCI manifest accept headers
			req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json")
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return data, resp.Header, resp.StatusCode, nil
}

func (p *ProxyServer) cacheData(cachePath string, data []byte) error {
	dir := filepath.Dir(cachePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

func (p *ProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestPath := r.URL.Path
	log.Printf("[%s] Request: %s %s", p.proxyType, r.Method, requestPath)

	// Handle root/health check
	if requestPath == "/" || requestPath == "/health" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":   "ok",
			"service":  fmt.Sprintf("%s-proxy", p.proxyType),
			"upstream": p.upstreamURL,
			"version":  "1.0.0",
		})
		return
	}

	cachePath := p.getCachePath(requestPath)

	// Check cache
	if p.isCached(cachePath) {
		log.Printf("[%s] Cache HIT: %s", p.proxyType, requestPath)
		data, err := os.ReadFile(cachePath)
		if err == nil {
			p.writeResponse(w, data, requestPath, true)
			return
		}
		log.Printf("[%s] Cache read error: %v", p.proxyType, err)
	}

	// Fetch from upstream
	data, headers, statusCode, err := p.fetchFromUpstream(requestPath, r.Header)
	if err != nil {
		log.Printf("[%s] Error fetching: %v", p.proxyType, err)
		http.Error(w, "Failed to fetch from upstream", http.StatusBadGateway)
		return
	}

	if statusCode != http.StatusOK {
		log.Printf("[%s] Upstream returned status: %d", p.proxyType, statusCode)
		// Forward important headers
		for key, values := range headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(statusCode)
		w.Write(data)
		return
	}

	// Cache successful responses
	if err := p.cacheData(cachePath, data); err != nil {
		log.Printf("[%s] Failed to cache: %v", p.proxyType, err)
	}

	// Copy important headers from upstream
	if contentType := headers.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if dockerContentDigest := headers.Get("Docker-Content-Digest"); dockerContentDigest != "" {
		w.Header().Set("Docker-Content-Digest", dockerContentDigest)
	}

	p.writeResponse(w, data, requestPath, false)
}

func (p *ProxyServer) writeResponse(w http.ResponseWriter, data []byte, path string, cached bool) {
	if w.Header().Get("Content-Type") == "" {
		contentType := p.getContentType(path)
		w.Header().Set("Content-Type", contentType)
	}

	if cached {
		w.Header().Set("X-Cache", "HIT")
	} else {
		w.Header().Set("X-Cache", "MISS")
	}

	w.Header().Set("X-Proxy-Type", string(p.proxyType))
	w.Write(data)
}

func (p *ProxyServer) getContentType(path string) string {
	switch p.proxyType {
	case NPMProxy:
		if strings.HasSuffix(path, ".tgz") {
			return "application/octet-stream"
		}
		return "application/json"
	case GoProxy:
		if strings.HasSuffix(path, ".info") || strings.HasSuffix(path, ".mod") {
			return "text/plain; charset=utf-8"
		} else if strings.HasSuffix(path, ".zip") {
			return "application/zip"
		}
		return "text/plain; charset=utf-8"
	case OCIProxy:
		if strings.Contains(path, "/manifests/") {
			return "application/vnd.docker.distribution.manifest.v2+json"
		} else if strings.Contains(path, "/blobs/") {
			return "application/octet-stream"
		}
		return "application/json"
	}
	return "application/octet-stream"
}

func (p *ProxyServer) clearCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	proxyCache := filepath.Join(p.cacheDir, string(p.proxyType))
	err := os.RemoveAll(proxyCache)
	if err != nil {
		http.Error(w, "Failed to clear cache", http.StatusInternalServerError)
		return
	}

	err = os.MkdirAll(proxyCache, 0755)
	if err != nil {
		http.Error(w, "Failed to recreate cache directory", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": fmt.Sprintf("%s cache cleared successfully", p.proxyType),
	})
}

func startProxy(proxyType ProxyType, port, upstreamURL string) {
	proxy := NewProxyServer(proxyType, cacheDir, upstreamURL)

	if err := proxy.ensureCacheDir(); err != nil {
		log.Fatalf("[%s] Failed to create cache directory: %v", proxyType, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", proxy.handleRequest)
	mux.HandleFunc("/_admin/clear-cache", proxy.clearCache)

	server := &http.Server{
		Addr:    port,
		Handler: mux,
	}

	log.Printf("[%s] Proxy starting on %s", proxyType, port)
	log.Printf("[%s] Upstream: %s", proxyType, upstreamURL)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[%s] Server failed: %v", proxyType, err)
	}
}

func main() {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Fatalf("Failed to create cache directory: %v", err)
	}

	log.Println("=== Multi-Protocol Dependency Proxy ===")
	log.Printf("Cache directory: %s\n", cacheDir)

	log.Println("\n📦 NPM Proxy:")
	log.Printf("  Port: %s", npmPort)
	log.Printf("  Configure: npm config set registry http://localhost%s\n", npmPort)

	log.Println("🐹 Go Proxy:")
	log.Printf("  Port: %s", goPort)
	log.Printf("  Configure: export GOPROXY=http://localhost%s\n", goPort)

	log.Println("🐳 OCI/Docker Proxy:")
	log.Printf("  Port: %s", ociPort)
	log.Printf("  Configure: docker pull localhost%s/library/alpine:latest\n", ociPort)

	log.Println("\n⚠️  Note: OCI proxy requires authentication passthrough for private registries")
	log.Println()

	// Start each proxy in its own goroutine
	go startProxy(NPMProxy, npmPort, npmRegistry)
	go startProxy(GoProxy, goPort, goProxyURL)

	// Main goroutine runs OCI proxy
	startProxy(OCIProxy, ociPort, dockerRegistry)
}
