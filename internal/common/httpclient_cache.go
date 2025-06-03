package common

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	cache *expirable.LRU[string, *http.Response]
}

func NewCacheTransport(cacheSize int, expiration time.Duration) *CacheTransport {
	cache := expirable.NewLRU[string, *http.Response](cacheSize, nil, expiration)
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
			return cloneResponse(val)
		}

		resp, err := next.RoundTrip(req)
		if err != nil {
			return resp, err
		}

		// only cache successful responses
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return resp, nil
		}

		cloned, err := cloneResponse(resp)
		if err == nil {
			c.cache.Add(key, cloned)
		}

		return resp, nil
	}
}

func cloneResponse(src *http.Response) (*http.Response, error) {
	if src.Body == nil {
		return nil, errors.New("nil body")
	}
	bodyBytes, err := io.ReadAll(src.Body)
	if err != nil {
		return nil, err
	}
	src.Body.Close()
	src.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	cloned := *src
	cloned.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return &cloned, nil
}

func cacheKey(req *http.Request) string {
	key := req.URL.String()

	// Include Authorization and Cookie headers if present
	auth := req.Header.Get("Authorization")
	cookie := req.Header.Get("Cookie")

	if auth != "" || cookie != "" {
		h := sha256.New()
		h.Write([]byte(key))
		h.Write([]byte(auth))
		h.Write([]byte(cookie))
		return fmt.Sprintf("%x", h.Sum(nil))
	}

	return key
}
