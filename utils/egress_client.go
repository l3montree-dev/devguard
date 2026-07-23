// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package utils

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/l3montree-dev/devguard/config"
	"github.com/l3montree-dev/devguard/utils"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/time/rate"
)

// EgressTransport is the shared RoundTripper for all outgoing HTTP calls.
// It adds User-Agent and OpenTelemetry trace propagation headers.
var EgressTransport http.RoundTripper = otelhttp.NewTransport(EgressRoundTripper{
	R: http.DefaultTransport,
})

func NewEgressClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: EgressTransport,
	}
}

var EgressClient = *NewEgressClient(30 * time.Second)

type EgressRoundTripper struct {
	R http.RoundTripper
}

// perHostLimiters is bounded (LRU-evicted) and TTL-expired so a process that sees many distinct
// (or attacker-controlled, e.g. webhook) hosts over its lifetime can't grow this map unbounded.
var perHostLimiters = expirable.NewLRU[string, *rate.Limiter](maxTrackedHosts, nil, hostLimiterTTL)

const (
	hostRateLimit   = 10 // requests per second per host
	hostBurst       = 20
	maxTrackedHosts = 4096
	hostLimiterTTL  = 10 * time.Minute
)

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.String() == "169.254.169.254"
}

func limiterForHost(host string) *rate.Limiter {
	if v, ok := perHostLimiters.Get(host); ok {
		return v
	}

	limiter := rate.NewLimiter(rate.Limit(hostRateLimit), hostBurst)
	perHostLimiters.Add(host, limiter)
	return limiter
}

func isBlockedHost(host string) bool {
	if testing.Testing() {
		// Allow egress to loopback/local test servers (e.g. httptest.Server) when running under
		// `go test`. testing.Testing() is only ever true in binaries built by the go test tool.
		return false
	}

	if strings.EqualFold(host, "localhost") {
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		// this is a cloud-metadata IP address, block it
		return isBlockedIP(ip)
	}

	// resolve the hostname to an IP address and check if it's blocked
	ips, err := net.LookupIP(host)
	if err != nil {
		// if we can't resolve the hostname, we can't determine if it's blocked or not
		// so we will allow it to go through
		return false
	}

	for _, ip := range ips {
		return isBlockedIP(ip)
	}

	return false
}

func (mrt EgressRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.UserAgent() == "" {
		r.Header.Set("User-Agent", config.UserAgent)
	}

	host := strings.ToLower(strings.TrimSuffix(r.URL.Hostname(), "."))
	if isBlockedHost(host) {
		return nil, fmt.Errorf("egress to host %q is blocked", host)
	}

	limiter := limiterForHost(host)
	if err := limiter.Wait(r.Context()); err != nil {
		return nil, err
	}

	return mrt.R.RoundTrip(r)
}

// executes a GET request with an empty body to the specified url
// if no client is passed, the function uses the default http client
// returns the io.ReadCloser of the body of the response, callers are responsible for closing it
func DoGetRequestWithContext(ctx context.Context, url string, client *http.Client) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("could not build http request: %w", err)
	}

	if client == nil {
		client = utils.EgressClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not execute http request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("request was unsuccessful, status code: %d", resp.StatusCode)
	}

	return resp.Body, nil
}
