package common

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

func WrapHTTPClient(client *http.Client, wrap func(req *http.Request, next http.RoundTripper) (*http.Response, error)) {
	if client == nil {
		return
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}

	client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return wrap(req, base)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type CacheTransport struct {
	cache *expirable.LRU[string, []byte]
}

func NewCacheTransport(cacheSize int, expiration time.Duration) *CacheTransport {
	cache := expirable.NewLRU[string, []byte](cacheSize, nil, expiration)
	return &CacheTransport{
		cache: cache,
	}
}

func (c *CacheTransport) Handler() func(req *http.Request, next http.RoundTripper) (*http.Response, error) {
	return func(req *http.Request, next http.RoundTripper) (*http.Response, error) {
		if req.Method != http.MethodGet {
			return next.RoundTrip(req)
		}

		key := cacheKey(req)

		if val, ok := c.cache.Get(key); ok {
			slog.Info("Cache hit", "url", req.URL.String())
			resp, err := responseFromBytes(val)
			if err != nil {
				slog.Error("Failed to read response from cache", "err", err)
				return nil, err
			}
			return resp, nil
		}

		resp, err := next.RoundTrip(req)
		if err != nil {
			return resp, err
		}

		// only cache successful responses
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return resp, nil
		}

		v, err := httputil.DumpResponse(resp, true)
		if err != nil {
			slog.Error("Failed to dump response", "err", err)
			return resp, nil
		}

		c.cache.Add(key, v)

		return responseFromBytes(v)
	}
}

func responseFromBytes(v []byte) (*http.Response, error) {
	r := bufio.NewReader(bytes.NewReader(v))
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	return resp, nil
}

func cacheKey(req *http.Request) string {
	key := req.URL.String()

	// Include Authorization and Cookie headers if present
	auth := req.Header.Get("Authorization")
	cookie := req.Header.Get("Cookie")
	privateToken := req.Header.Get("Private-Token")

	if auth != "" || cookie != "" || privateToken != "" {
		h := sha256.New()
		h.Write([]byte(key))
		h.Write([]byte(auth))
		h.Write([]byte(cookie))
		h.Write([]byte(privateToken))
		return fmt.Sprintf("%x", h.Sum(nil))
	}

	return key
}
