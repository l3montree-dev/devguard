package config

import (
	"encoding/json"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

type configRepository interface {
	Save(tx core.DB, config *models.Config) error
	GetDB(tx core.DB) core.DB
}
type Service struct {
	repository configRepository
}

func NewService(db core.DB) Service {
	repository := repositories.NewConfigRepository(db)
	return Service{
		repository: repository,
	}
}

func (service Service) GetJSONConfig(key string, v any) error {
	var config models.Config
	if err := service.repository.GetDB(nil).Where("key = ?", key).First(&config).Error; err != nil {
		return err
	}

	return json.Unmarshal([]byte(config.Val), v)
}

func (service Service) SetJSONConfig(key string, v any) error {
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
