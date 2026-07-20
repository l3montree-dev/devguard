package accesscontrol

import (
	"net/http"
	"time"

	"github.com/l3montree-dev/devguard/config"
	"github.com/ory/client-go"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

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
var oryTransport http.RoundTripper = otelhttp.NewTransport(oryRoundTripper{
	R: http.DefaultTransport,
})

var oryHTTPClient = http.Client{
	Timeout:   30 * time.Second,
	Transport: oryTransport,
}

type oryRoundTripper struct {
	R http.RoundTripper
}

func (mrt oryRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.UserAgent() == "" {
		r.Header.Set("User-Agent", config.UserAgent)
	}

	return mrt.R.RoundTrip(r)
}

func GetOryAPIClient(url string) *client.APIClient {
	cfg := client.NewConfiguration()
	cfg.Servers = client.ServerConfigurations{
		{URL: url},
	}
	cfg.HTTPClient = &oryHTTPClient

	ory := client.NewAPIClient(cfg)
	return ory
}
