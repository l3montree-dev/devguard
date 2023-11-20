package service

import "github.com/google/uuid"

type EnvService struct {
}

type EnvState = string

func NewEnvService() *EnvService {
	return &EnvService{}
}

func (e *EnvService) GetCurrentState(envID uuid.UUID) (EnvState, error) {

}
