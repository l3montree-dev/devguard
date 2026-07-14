package dtos_test

import (
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
)

func TestPatCreateRequestExpireDateValidation(t *testing.T) {
	t.Run("accepts a timestamp 1 hour in the future", func(t *testing.T) {
		req := dtos.PatCreateRequest{Scopes: "scan", ExpiryDateUnix: time.Now().Add(time.Hour).Unix()}
		if err := dtos.V.Struct(req); err != nil {
			t.Fatalf("expected valid, got: %v", err)
		}
	})

	t.Run("accepts a timestamp exactly 1 year in the future", func(t *testing.T) {
		req := dtos.PatCreateRequest{Scopes: "scan", ExpiryDateUnix: time.Now().Add(365 * 24 * time.Hour).Unix()}
		if err := dtos.V.Struct(req); err != nil {
			t.Fatalf("expected valid, got: %v", err)
		}
	})

	t.Run("rejects a timestamp in the past", func(t *testing.T) {
		req := dtos.PatCreateRequest{Scopes: "scan", ExpiryDateUnix: time.Now().Add(-time.Hour).Unix()}
		if err := dtos.V.Struct(req); err == nil {
			t.Fatal("expected validation error for past timestamp")
		}
	})

	t.Run("rejects a timestamp more than 1 year in the future", func(t *testing.T) {
		req := dtos.PatCreateRequest{Scopes: "scan", ExpiryDateUnix: time.Now().Add(366 * 24 * time.Hour).Unix()}
		if err := dtos.V.Struct(req); err == nil {
			t.Fatal("expected validation error for timestamp beyond 1 year")
		}
	})

	t.Run("rejects zero value (missing expiry)", func(t *testing.T) {
		req := dtos.PatCreateRequest{Scopes: "scan", ExpiryDateUnix: 0}
		if err := dtos.V.Struct(req); err == nil {
			t.Fatal("expected validation error for zero expiry")
		}
	})
}
