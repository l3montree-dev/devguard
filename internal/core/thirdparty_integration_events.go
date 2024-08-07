package core

import "github.com/l3montree-dev/devguard/internal/database/models"

type ManualMitigateEvent struct {
	Ctx Context
}

type FlawEvent struct {
	Ctx   Context
	Event models.FlawEvent
}
