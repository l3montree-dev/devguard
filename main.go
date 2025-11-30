package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	npmRegistry         = "https://registry.npmjs.org"
	goProxyURL          = "https://proxy.golang.org"
	dockerRegistry      = "https://registry-1.docker.io"
	cacheDir            = "./cache"
	maliciousPackageDir = "./malicious-packages/osv/malicious"
	serverPort          = ":8080"
)

type ProxyType string

const (
	NPMProxy ProxyType = "npm"
	GoProxy  ProxyType = "go"
	OCIProxy ProxyType = "oci"
)

// MaliciousPackageEntry represents a malicious package from the OSV database
type MaliciousPackageEntry struct {
	ID        string     `json:"id"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Affected  []Affected `json:"affected"`
	Published string     `json:"published"`
}

type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges"`
	Versions []string `json:"versions"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// MaliciousPackageChecker checks packages against the malicious package database
type MaliciousPackageChecker struct {
	mu       sync.RWMutex
	packages map[string]map[string]*MaliciousPackageEntry // ecosystem -> package name -> entry
}

func NewMaliciousPackageChecker(dbPath string) (*MaliciousPackageChecker, error) {
	checker := &MaliciousPackageChecker{
		packages: make(map[string]map[string]*MaliciousPackageEntry),
	}

	if err := checker.loadDatabase(dbPath); err != nil {
		return nil, fmt.Errorf("failed to load malicious package database: %w", err)
	}

	return checker, nil
}

func (c *MaliciousPackageChecker) loadDatabase(dbPath string) error {
	slog.Info("Loading malicious package database", "path", dbPath)

	ecosystems := []string{"npm", "go", "maven", "pypi", "crates.io"}
	totalLoaded := 0

	// Use goroutines to load ecosystems in parallel
	var wg sync.WaitGroup
	resultChan := make(chan int, len(ecosystems))
	errorChan := make(chan error, len(ecosystems))

	for _, ecosystem := range ecosystems {
		ecosystemPath := filepath.Join(dbPath, ecosystem)
		if _, err := os.Stat(ecosystemPath); os.IsNotExist(err) {
			continue
		}

		wg.Add(1)
		go func(eco, ecoPath string) {
			defer wg.Done()
			count, err := c.loadEcosystem(ecoPath)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- count
			if count > 0 {
				slog.Info("Loaded malicious packages", "ecosystem", eco, "count", count)
			}
		}(ecosystem, ecosystemPath)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	close(resultChan)
	close(errorChan)

	// Collect results
	for count := range resultChan {
		totalLoaded += count
	}

	// Log any errors
	for err := range errorChan {
		slog.Warn("Error loading ecosystem", "error", err)
	}

	slog.Info("Malicious package database loaded", "total", totalLoaded)
	return nil
}

func (c *MaliciousPackageChecker) loadEcosystem(ecosystemPath string) (int, error) {
	// Collect all JSON files first
	var files []string
	err := filepath.Walk(ecosystemPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	// Process files in parallel batches
	const batchSize = 100
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent file reads

	for i := 0; i < len(files); i += batchSize {
		end := i + batchSize
		if end > len(files) {
			end = len(files)
		}

		batch := files[i:end]
		for _, path := range batch {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore

			go func(p string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore

				if err := c.loadPackageEntry(p); err != nil {
					slog.Debug("Failed to load malicious package entry", "path", p, "error", err)
				}
			}(path)
		}
	}

	wg.Wait()
	return len(files), nil
}

func (c *MaliciousPackageChecker) loadPackageEntry(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var entry MaliciousPackageEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return err
	}

	if len(entry.Affected) == 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, affected := range entry.Affected {
		pkgEcosystem := strings.ToLower(affected.Package.Ecosystem)
		pkgName := strings.ToLower(affected.Package.Name)

		if c.packages[pkgEcosystem] == nil {
			c.packages[pkgEcosystem] = make(map[string]*MaliciousPackageEntry)
		}

		c.packages[pkgEcosystem][pkgName] = &entry
	}

	return nil
}

func (c *MaliciousPackageChecker) IsMalicious(ecosystem, packageName, version string) (bool, *MaliciousPackageEntry) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ecosystemKey := strings.ToLower(ecosystem)
	packageKey := strings.ToLower(packageName)

	if ecosystemMap, ok := c.packages[ecosystemKey]; ok {
		if entry, ok := ecosystemMap[packageKey]; ok {
			// Check if the version is affected
			for _, affected := range entry.Affected {
				if c.isVersionAffected(affected, version) {
					return true, entry
				}
			}
		}
	}

	return false, nil
}

func (c *MaliciousPackageChecker) isVersionAffected(affected Affected, version string) bool {
	// If no specific versions or ranges, consider all versions affected
	if len(affected.Versions) == 0 && len(affected.Ranges) == 0 {
		return true
	}

	// Check explicit versions
	for _, v := range affected.Versions {
		if v == version || version == "" {
			return true
		}
	}

	// Check ranges
	for _, r := range affected.Ranges {
		if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
			for _, event := range r.Events {
				if event.Introduced == "0" && event.Fixed == "" {
					return true
				}
			}
		}
	}

	return false
}

type ProxyServer struct {
	proxyType        ProxyType
	cacheDir         string
	upstreamURL      string
	client           *http.Client
	maliciousChecker *MaliciousPackageChecker
}

type MultiProxyRouter struct {
	npmProxy *ProxyServer
	goProxy  *ProxyServer
	ociProxy *ProxyServer
}

func NewProxyServer(proxyType ProxyType, cacheDir, upstreamURL string, maliciousChecker *MaliciousPackageChecker) *ProxyServer {
	return &ProxyServer{
		proxyType:        proxyType,
		cacheDir:         cacheDir,
		upstreamURL:      upstreamURL,
		maliciousChecker: maliciousChecker,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func NewMultiProxyRouter(maliciousChecker *MaliciousPackageChecker) *MultiProxyRouter {
	return &MultiProxyRouter{
		npmProxy: NewProxyServer(NPMProxy, cacheDir, npmRegistry, maliciousChecker),
		goProxy:  NewProxyServer(GoProxy, cacheDir, goProxyURL, maliciousChecker),
		ociProxy: NewProxyServer(OCIProxy, cacheDir, dockerRegistry, maliciousChecker),
	}
}

func (r *MultiProxyRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path

	// Health check
	if path == "/" || path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "multi-protocol-proxy",
			"version": "1.0.0",
		}); err != nil {
			slog.Warn("Failed to write health check response", "error", err)
		}
		return
	}

	// Route based on path prefix
	switch {
	case strings.HasPrefix(path, "/npm/"):
		// Strip /npm prefix and forward to npm proxy
		req.URL.Path = strings.TrimPrefix(path, "/npm")
		r.npmProxy.handleRequest(w, req)
	case strings.HasPrefix(path, "/go/"):
		// Strip /go prefix and forward to go proxy
		req.URL.Path = strings.TrimPrefix(path, "/go")
		r.goProxy.handleRequest(w, req)
	case strings.HasPrefix(path, "/oci/") || strings.HasPrefix(path, "/v2/"):
		// Strip /oci prefix and forward to oci proxy (keep /v2 for Docker registry compatibility)
		if strings.HasPrefix(path, "/oci/") {
			req.URL.Path = strings.TrimPrefix(path, "/oci")
		}
		r.ociProxy.handleRequest(w, req)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(map[string]string{
			"error":    "Not Found",
			"message":  "Use /npm/, /go/, or /oci/ prefix to access the respective proxy",
			"examples": "GET /npm/lodash, GET /go/github.com/gin-gonic/gin/@v/list, GET /v2/library/alpine/manifests/latest",
		}); err != nil {
			slog.Warn("Failed to write not found response", "error", err)
		}
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
	slog.Debug("Fetching from upstream", "proxy", p.proxyType, "url", url)

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
	slog.Info("Request received", "proxy", p.proxyType, "method", r.Method, "path", requestPath)

	// Check for malicious packages
	if p.maliciousChecker != nil {
		if blocked, reason := p.checkMaliciousPackage(requestPath); blocked {
			slog.Warn("Blocked malicious package", "proxy", p.proxyType, "path", requestPath, "reason", reason)
			p.blockMaliciousPackage(w, requestPath, reason)
			return
		}
	}

	// Handle root/health check
	if requestPath == "/" || requestPath == "/health" {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{
			"status":   "ok",
			"service":  fmt.Sprintf("%s-proxy", p.proxyType),
			"upstream": p.upstreamURL,
			"version":  "1.0.0",
		}); err != nil {
			slog.Warn("Failed to write health check response", "proxy", p.proxyType, "error", err)
		}

		return
	}

	cachePath := p.getCachePath(requestPath)

	// Check cache
	if p.isCached(cachePath) {
		slog.Debug("Cache hit", "proxy", p.proxyType, "path", requestPath)
		data, err := os.ReadFile(cachePath)
		if err == nil {
			p.writeResponse(w, data, requestPath, true)
			return
		}
		slog.Warn("Cache read error", "proxy", p.proxyType, "error", err)
	}

	// Fetch from upstream
	data, headers, statusCode, err := p.fetchFromUpstream(requestPath, r.Header)
	if err != nil {
		slog.Error("Error fetching from upstream", "proxy", p.proxyType, "error", err)
		http.Error(w, "Failed to fetch from upstream", http.StatusBadGateway)
		return
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", p.proxyType, "status", statusCode)
		// Forward important headers
		for key, values := range headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(statusCode)
		if _, err := w.Write(data); err != nil {
			slog.Warn("Failed to write response", "proxy", p.proxyType, "error", err)
		}
		return
	}

	// Cache successful responses
	if err := p.cacheData(cachePath, data); err != nil {
		slog.Warn("Failed to cache response", "proxy", p.proxyType, "error", err)
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
	if _, err := w.Write(data); err != nil {
		slog.Warn("Failed to write response", "proxy", p.proxyType, "error", err)
	}
}

// parsePackageFromPath extracts package name and version from request path
func (p *ProxyServer) parsePackageFromPath(path string) (string, string) {
	switch p.proxyType {
	case NPMProxy:
		// NPM paths: /<package> or /@scope/<package> or /<package>/-/<package>-<version>.tgz
		if strings.HasSuffix(path, ".tgz") {
			// Extract from tarball path: /<package>/-/<package>-<version>.tgz
			parts := strings.Split(path, "/-/")
			if len(parts) == 2 {
				pkgName := strings.TrimPrefix(parts[0], "/")
				// Extract version from filename
				filename := strings.TrimSuffix(parts[1], ".tgz")
				// Remove package name prefix to get version
				version := strings.TrimPrefix(filename, strings.ReplaceAll(pkgName, "/", "-")+"-")
				return pkgName, version
			}
		}
		// Metadata request: /<package>
		pkgName := strings.TrimPrefix(path, "/")
		return pkgName, ""

	case GoProxy:
		// Go paths: /<module>/@v/<version>.info, /<module>/@v/<version>.mod, etc.
		re := regexp.MustCompile(`^/([^@]+)(?:@v/([^/]+))?`)
		matches := re.FindStringSubmatch(path)
		if len(matches) > 1 {
			moduleName := matches[1]
			version := ""
			if len(matches) > 2 && matches[2] != "" {
				// Skip special endpoints like "list"
				if matches[2] == "list" {
					return moduleName, ""
				}
				version = strings.TrimSuffix(strings.TrimSuffix(matches[2], ".info"), ".mod")
				version = strings.TrimSuffix(version, ".zip")
			}
			return moduleName, version
		}

	case OCIProxy:
		// OCI paths: /v2/<name>/manifests/<reference> or /v2/<name>/blobs/<digest>
		re := regexp.MustCompile(`^/v2/([^/]+(?:/[^/]+)*)/(?:manifests|blobs)/(.+)$`)
		matches := re.FindStringSubmatch(path)
		if len(matches) > 2 {
			return matches[1], matches[2]
		}
	}

	return "", ""
}

func (p *ProxyServer) checkMaliciousPackage(path string) (bool, string) {
	packageName, version := p.parsePackageFromPath(path)
	if packageName == "" {
		return false, ""
	}

	ecosystem := ""
	switch p.proxyType {
	case NPMProxy:
		ecosystem = "npm"
	case GoProxy:
		ecosystem = "go"
	case OCIProxy:
		// Could map to docker/oci ecosystem
		return false, ""
	}

	slog.Debug("Checking package against malicious database", "ecosystem", ecosystem, "package", packageName, "version", version)

	isMalicious, entry := p.maliciousChecker.IsMalicious(ecosystem, packageName, version)
	if isMalicious {
		reason := fmt.Sprintf("Package %s is flagged as malicious (ID: %s)", packageName, entry.ID)
		if entry.Summary != "" {
			reason += ": " + entry.Summary
		}
		return true, reason
	}

	return false, ""
}

func (p *ProxyServer) blockMaliciousPackage(w http.ResponseWriter, path, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Malicious-Package", "blocked")
	w.WriteHeader(http.StatusForbidden)

	response := map[string]interface{}{
		"error":   "Forbidden",
		"message": "This package has been blocked by the malicious package firewall",
		"reason":  reason,
		"path":    path,
		"blocked": true,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Warn("Failed to write malicious block response", "proxy", p.proxyType, "error", err)
	}
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

func startMultiProxy(maliciousChecker *MaliciousPackageChecker) {
	router := NewMultiProxyRouter(maliciousChecker)

	// Ensure cache directories exist for all proxies
	for _, proxy := range []*ProxyServer{router.npmProxy, router.goProxy, router.ociProxy} {
		if err := proxy.ensureCacheDir(); err != nil {
			slog.Error("Failed to create cache directory", "proxy", proxy.proxyType, "error", err)
			os.Exit(1)
		}
	}

	// Add admin endpoints
	mux := http.NewServeMux()
	mux.Handle("/", router)

	server := &http.Server{
		Addr:    serverPort,
		Handler: mux,
	}

	slog.Info("Multi-protocol proxy starting", "port", serverPort)
	slog.Info("NPM endpoint", "path", "/npm/*", "upstream", npmRegistry)
	slog.Info("Go endpoint", "path", "/go/*", "upstream", goProxyURL)
	slog.Info("OCI/Docker endpoint", "path", "/v2/*", "upstream", dockerRegistry)

	if err := server.ListenAndServe(); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}

func main() {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		slog.Error("Failed to create cache directory", "error", err)
		os.Exit(1)
	}

	slog.Info("Starting Multi-Protocol Dependency Proxy with Malicious Package Firewall")
	slog.Info("Cache directory configured", "path", cacheDir)

	// Load malicious package database
	slog.Info("Initializing malicious package firewall")
	maliciousChecker, err := NewMaliciousPackageChecker(maliciousPackageDir)
	if err != nil {
		slog.Warn("Could not load malicious package database", "error", err)
		slog.Info("Continuing without malicious package protection")
		maliciousChecker = nil
	} else {
		slog.Info("Malicious package firewall enabled")
	}

	slog.Info("Configuration examples:")
	slog.Info("NPM:", "command", fmt.Sprintf("npm config set registry http://localhost%s/npm", serverPort))
	slog.Info("Go:", "command", fmt.Sprintf("export GOPROXY=http://localhost%s/go", serverPort))
	slog.Info("Docker:", "note", "Use registry mirror configuration (see README)")
	slog.Info("Note: OCI proxy requires authentication passthrough for private registries")

	// Start single server with path-based routing
	startMultiProxy(maliciousChecker)
}
