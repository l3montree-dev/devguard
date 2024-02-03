package config

import (
	"encoding/json"

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type Service struct {
	repository database.Repository[string, Config, core.DB]
}

func NewService(db core.DB) Service {
	repository := NewGormRepository(db)
	return Service{
		repository: repository,
	}
}

func (service Service) GetJSONConfig(key string, v any) error {
	var config Config
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

	config := Config{
		Key: key,
		Val: string(b),
	}

	return service.repository.Save(nil, &config)
}
