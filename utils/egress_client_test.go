package utils

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback
		"::1",             // loopback (v6)
		"169.254.169.254", // cloud metadata / link-local
		"169.254.1.1",     // link-local
		"0.0.0.0",         // unspecified
	}
	for _, s := range blocked {
		assert.True(t, isBlockedIP(net.ParseIP(s)), "expected %q to be blocked", s)
	}

	notBlocked := []string{
		"8.8.8.8",
		"203.0.113.1", // RFC 5737 documentation range - public-looking, non-loopback/link-local
		"2001:db8::1", // RFC 3849 documentation range
	}
	for _, s := range notBlocked {
		assert.False(t, isBlockedIP(net.ParseIP(s)), "expected %q not to be blocked", s)
	}
}

func TestSafeDialContextBlocksLiteralLoopbackIP(t *testing.T) {
	_, err := safeDialContext(context.Background(), "tcp", "127.0.0.1:80")
	assert.ErrorContains(t, err, "blocked")
}

func TestSafeDialContextBlocksLiteralMetadataIP(t *testing.T) {
	_, err := safeDialContext(context.Background(), "tcp", "169.254.169.254:80")
	assert.ErrorContains(t, err, "blocked")
}

// TestSafeDialContextBlocksHostnameResolvingToLoopback is the actual DNS-bypass this fix closes:
// "localhost" is not a literal IP, so the old hostname-string-only check (net.ParseIP(host) == nil)
// let it through; safeDialContext must resolve it and reject the resulting loopback address.
func TestSafeDialContextBlocksHostnameResolvingToLoopback(t *testing.T) {
	_, err := safeDialContext(context.Background(), "tcp", "localhost:80")
	assert.ErrorContains(t, err, "blocked")
}

func TestSafeDialContextAllowsNonBlockedLiteralIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := safeDialContext(ctx, "tcp", "203.0.113.1:80")
	// RFC 5737 TEST-NET-3 is guaranteed non-routable, so the dial itself will fail/time out -
	// what matters is that it's NOT rejected by the blocklist.
	if err != nil {
		assert.NotContains(t, err.Error(), "blocked")
	}
}

func TestLimiterForHostReturnsSameLimiterForSameHost(t *testing.T) {
	a := limiterForHost("example.com")
	b := limiterForHost("example.com")
	assert.Same(t, a, b)
}

func TestLimiterForHostReturnsDifferentLimitersForDifferentHosts(t *testing.T) {
	a := limiterForHost("host-a.example.com")
	b := limiterForHost("host-b.example.com")
	assert.NotSame(t, a, b)
}

func TestPerHostLimitersIsBounded(t *testing.T) {
	for i := 0; i < maxTrackedHosts+100; i++ {
		limiterForHost(fmt.Sprintf("host-%d.example.com", i))
	}

	assert.LessOrEqual(t, perHostLimiters.Len(), maxTrackedHosts,
		"perHostLimiters must never grow past maxTrackedHosts, regardless of how many distinct hosts are seen")
}
