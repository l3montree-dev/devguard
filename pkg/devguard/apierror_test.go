package devguard

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAPIError(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"echo HTTPError string", `"could not find asset"`, "403 Forbidden: could not find asset"},
		{"message object", `{"message":"invalid token"}`, "403 Forbidden: invalid token"},
		{"error object", `{"error":"could not find organization"}`, "403 Forbidden: could not find organization"},
		{"plain text", "  upstream unavailable\n", "403 Forbidden: upstream unavailable"},
		{"empty body", "", "403 Forbidden"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Status: "403 Forbidden", Body: io.NopCloser(strings.NewReader(tc.body))}
			assert.EqualError(t, NewAPIError(resp), tc.want)
		})
	}
}
