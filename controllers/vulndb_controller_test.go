package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestEcosystemDistributionCache(t *testing.T) {
	t.Run("returns nothing when empty", func(t *testing.T) {
		cache := &ecosystemDistributionCache{}

		_, found := cache.get()

		assert.False(t, found)
	})

	t.Run("returns the cached value before expiry", func(t *testing.T) {
		cache := &ecosystemDistributionCache{}
		cache.set(map[string]int{"golang": 42, "npm": 7})

		value, found := cache.get()

		assert.True(t, found)
		assert.Equal(t, map[string]int{"golang": 42, "npm": 7}, value)
	})

	t.Run("returns nothing after expiry", func(t *testing.T) {
		cache := &ecosystemDistributionCache{}
		cache.set(map[string]int{"golang": 42})
		cache.expiryTime = time.Now().Add(-time.Second)

		_, found := cache.get()

		assert.False(t, found)
	})
}

func TestGetCVEEcosystemDistributionServesFromCache(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	// the repository stays nil - any database access would panic, which proves
	// a cache hit never touches the database
	controller := &VulnDBController{
		ecosystemDistributionCache: &ecosystemDistributionCache{},
	}
	controller.ecosystemDistributionCache.set(map[string]int{"golang": 42, "npm": 7})

	err := controller.GetCVEEcosystemDistribution(ctx)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]int
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, map[string]int{"golang": 42, "npm": 7}, body)
}
