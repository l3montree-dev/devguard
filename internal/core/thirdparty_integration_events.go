package core

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type ManualMitigateEvent struct {
	Ctx           Context
	Justification string
}

type VulnEvent struct {
	Ctx   Context
	Event models.VulnEvent
}

type SBOMCreatedEvent struct {
	Ctx  Context
	SBOM cdx.BOM
}
