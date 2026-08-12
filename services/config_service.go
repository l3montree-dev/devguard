package services

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"

	"github.com/l3montree-dev/devguard/shared"
)

type ConfigService struct {
	repository shared.ConfigRepository
}

func NewConfigService(db shared.DB) ConfigService {
	repository := repositories.NewConfigRepository(db)
	return ConfigService{
		repository: repository,
	}
}

var _ shared.ConfigService = (*ConfigService)(nil) // Ensure ConfigService implements shared.ConfigService interface

func (service ConfigService) GetJSONConfig(ctx context.Context, key string, v any) error {
	var config models.Config
	if err := service.repository.GetDB(ctx, nil).Where("key = ?", key).First(&config).Error; err != nil {
		return err
	}

	return json.Unmarshal([]byte(config.Val), v)
}

func (service ConfigService) SetJSONConfig(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	config := models.Config{
		Key: key,
		Val: string(b),
	}

	if err := service.repository.Save(ctx, nil, &config); err != nil {
		return err
	}

	// Keep the in-memory instance settings cache in sync with the DB write
	if key == "instanceSettings" {
		if settings, ok := v.(shared.InstanceSettings); ok {
			settingsCache.UpdateCachedSettings(&settings)
		}
	}

	return nil
}

func (service ConfigService) RemoveConfig(ctx context.Context, key string) error {
	return service.repository.GetDB(ctx, nil).Where("key = ?", key).Delete(&models.Config{}).Error
}

func (service ConfigService) GetInstanceSettings(ctx context.Context) (shared.InstanceSettings, error) {
	cachedSettings, ok := settingsCache.GetCachedSettings()
	if ok {
		return cachedSettings, nil
	}

	var settings shared.InstanceSettings
	err := service.GetJSONConfig(ctx, "instanceSettings", &settings)
	//if there is an error, we return default settings from environment variables
	if err != nil {
		singleOrganizationMode := os.Getenv("SINGLE_ORGANIZATION_MODE")
		if singleOrganizationMode == "true" {
			settings.SingleOrganizationMode = true
		} else {
			settings.SingleOrganizationMode = false
		}
		bearerTokenAuthDisabled := os.Getenv("BEARER_TOKEN_AUTH_DISABLED")
		if bearerTokenAuthDisabled == "true" {
			settings.BearerTokenAuthDisabled = true
		} else {
			settings.BearerTokenAuthDisabled = false
		}
	}
	// one could argue that we should only update when we hit NO error
	// I think its a tradeoff between correctness and caching effectiveness
	settingsCache.UpdateCachedSettings(&settings)
	return settings, nil
}

var settingsCache = NewInstanceSettingsCache()

// cache instance settings, no time to life since we know when they change
type instanceSettingsCache struct {
	cachedSettings *shared.InstanceSettings
	mutex          *sync.RWMutex
}

func NewInstanceSettingsCache() instanceSettingsCache {
	return instanceSettingsCache{
		mutex: &sync.RWMutex{},
	}
}

// retrieves the cached settings, returns bool to check if anything is cached
func (cache *instanceSettingsCache) GetCachedSettings() (shared.InstanceSettings, bool) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	if cache.cachedSettings == nil {
		return shared.InstanceSettings{}, false
	}
	return *cache.cachedSettings, true
}

// updates the cached settings with new ones
func (cache *instanceSettingsCache) UpdateCachedSettings(settings *shared.InstanceSettings) {
	if settings != nil { // only update if values are provided
		cache.mutex.Lock()
		defer cache.mutex.Unlock()
		cache.cachedSettings = settings
	}
}

// checks if the provided settings are identical to the cached settings
func checkIfSettingsAreEqualToCache(settings shared.InstanceSettings) bool {
	cachedSettings, ok := settingsCache.GetCachedSettings()
	if !ok { // nothing cached so far -> false
		return false
	}
	// check if all values match
	return settings.BearerTokenAuthDisabled == cachedSettings.BearerTokenAuthDisabled &&
		settings.SingleOrganizationMode == cachedSettings.SingleOrganizationMode
}
