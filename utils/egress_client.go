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
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/config"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/time/rate"
)

// EgressTransport is the shared RoundTripper for all outgoing HTTP calls.
// It adds User-Agent and OpenTelemetry trace propagation headers.
var EgressTransport http.RoundTripper = otelhttp.NewTransport(EgressRoundTripper{
	R: http.DefaultTransport,
})

var EgressClient = http.Client{
	Timeout:   30 * time.Second,
	Transport: EgressTransport,
}

type EgressRoundTripper struct {
	R http.RoundTripper
}

var perHostLimiters sync.Map // map[string]*rate.Limiter

const (
	hostRateLimit = 10 // requests per second per host
	hostBurst     = 20
)

func limiterForHost(host string) *rate.Limiter {
	if v, ok := perHostLimiters.Load(host); ok {
		return v.(*rate.Limiter)
	}

	limiter := rate.NewLimiter(rate.Limit(hostRateLimit), hostBurst)
	actual, _ := perHostLimiters.LoadOrStore(host, limiter)
	return actual.(*rate.Limiter)
}

func isBlockedHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		// this is a cloud-metadata IP address, block it
		return ip.IsLoopback() || ip.String() == "169.254.169.254"
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
