package events

import (
	"time"

	"github.com/google/uuid"
)

const (
	ArtifactCreated = "artifact.created"
)

// events/events.go
type ArtifactCreatedPayload struct {
	ArtifactName     string
	AssetVersionName string
	AssetID          uuid.UUID
	CreatedAt        time.Time
}
