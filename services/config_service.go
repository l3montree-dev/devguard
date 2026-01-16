package services

import (
	"encoding/json"

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

func (service ConfigService) GetJSONConfig(key string, v any) error {
	var config models.Config
	if err := service.repository.GetDB(nil).Where("key = ?", key).First(&config).Error; err != nil {
		return err
	}

	return json.Unmarshal([]byte(config.Val), v)
}

func (service ConfigService) SetJSONConfig(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	config := models.Config{
		Key: key,
		Val: string(b),
	}

	return service.repository.Save(nil, &config)
}

func (service ConfigService) RemoveConfig(key string) error {
	return service.repository.GetDB(nil).Where("key = ?", key).Delete(&models.Config{}).Error
}
