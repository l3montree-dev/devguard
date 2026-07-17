package utils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback
		"::1",             // loopback (v6)
		"169.254.169.254", // cloud metadata / link-local
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
