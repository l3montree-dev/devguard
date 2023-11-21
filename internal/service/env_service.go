package service

import (
	"github.com/google/uuid"
)

type envRepository interface {
}

type EnvService struct {
	envRepository
}

type EnvState = string

func NewEnvService(
	envRepository envRepository,
) *EnvService {
	return &EnvService{
		envRepository: envRepository,
	}
}

func (e *EnvService) GetCurrentState(envID uuid.UUID) (EnvState, error) {
	return "running", nil
}
