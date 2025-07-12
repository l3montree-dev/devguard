package common

import (
	"log/slog"
	"net/http"

	"golang.org/x/sync/singleflight"
)

type DeduplicationTransport struct {
	group singleflight.Group
}

func NewDeduplicationTransport() *DeduplicationTransport {
	return &DeduplicationTransport{
		group: singleflight.Group{},
	}
}

func (c *DeduplicationTransport) Handler() func(req *http.Request, next http.RoundTripper) (*http.Response, error) {
	return func(req *http.Request, next http.RoundTripper) (*http.Response, error) {
		if req.Method != http.MethodGet {
			return next.RoundTrip(req)
		}

		key := cacheKey(req)

		resp, err, shared := c.group.Do(key, func() (any, error) {
			resp, err := next.RoundTrip(req)
			if err != nil {
				return nil, err
			}

			return resp, nil
		})

		if shared {
			slog.Debug("deduplicated request",
				"method", req.Method,
				"url", req.URL.String())
		}
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return nil, nil
		}
		return cloneResponse(resp.(*http.Response))
	}
}
