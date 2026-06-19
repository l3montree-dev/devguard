package services

import (
	"context"
	"encoding/json"
	"os"
	"time"

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

	return service.repository.Save(ctx, nil, &config)
}

func (service ConfigService) RemoveConfig(ctx context.Context, key string) error {
	return service.repository.GetDB(ctx, nil).Where("key = ?", key).Delete(&models.Config{}).Error
}

var instanceSettingsCache *shared.InstanceSettings
var instanceSettingsExpiry time.Time

func (service ConfigService) GetInstanceSettings(ctx context.Context) (shared.InstanceSettings, error) {
	if instanceSettingsCache != nil && time.Now().Before(instanceSettingsExpiry) {
		return *instanceSettingsCache, nil
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

	instanceSettingsCache = &settings
	instanceSettingsExpiry = time.Now().Add(5 * time.Minute) // cache for 5 minutes

	return settings, nil
}

func (service ConfigService) GetAndCacheInstanceSettings(ctx context.Context) (shared.InstanceSettings, error) {

	settings, err := service.GetInstanceSettings(ctx)
	if err != nil {
		return shared.InstanceSettings{}, err
	}

	return settings, nil
}
