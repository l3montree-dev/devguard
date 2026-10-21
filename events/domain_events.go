package events

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/monitoring"
)

// Domain events state what happened - the listeners decide what follows, see daemons.RegisterJobs.
// They are notified after the change is committed: a listener might run before an open transaction finishes.
// Notifying is best effort - a failure is logged, the sweep of the asset pipeline catches up on the follow-up work.
const (
	TopicSBOMCreated                NotifyTopic = "artifact.sbomCreated"
	TopicDependencyVulnsDetected    NotifyTopic = "artifact.dependencyVulnsDetected"
	TopicArtifactDeleted            NotifyTopic = "artifact.deleted"
	TopicFirstPartyScanned          NotifyTopic = "assetVersion.firstPartyScanned"
	TopicAssetVersionDeleted        NotifyTopic = "assetVersion.deleted"
	TopicVEXRuleCreated             NotifyTopic = "vexRule.created"
	TopicVEXRuleDeleted             NotifyTopic = "vexRule.deleted"
	TopicAssetTicketSettingsChanged NotifyTopic = "asset.ticketSettingsChanged"
)

// Payload is implemented by every job payload - a failing job names the context of its payload in the alert
type Payload interface {
	AlertContext() monitoring.AlertContext
}

// EmptyPayload is the payload of the jobs which need none, e.g. the scheduled daemons
type EmptyPayload struct{}

func (EmptyPayload) AlertContext() monitoring.AlertContext {
	return monitoring.AlertContext{}
}

// AssetPayload names the asset an event happened on
type AssetPayload struct {
	AssetID uuid.UUID `json:"assetId"`
}

func (p AssetPayload) AlertContext() monitoring.AlertContext {
	return monitoring.AlertContext{AssetID: p.AssetID}
}

// ArtifactPayload names the artifact an event happened on - the listeners load everything else themselves, so a retry never works on stale data.
// ArtifactName is empty for events of the whole asset version.
type ArtifactPayload struct {
	AssetID          uuid.UUID `json:"assetId"`
	AssetVersionName string    `json:"assetVersionName"`
	ArtifactName     string    `json:"artifactName,omitempty"`
	UserAgent        string    `json:"userAgent,omitempty"`
	// the vulns a scan opened
	VulnIDs []uuid.UUID `json:"vulnIds,omitempty"`
}

func (p ArtifactPayload) AlertContext() monitoring.AlertContext {
	return monitoring.AlertContext{AssetID: p.AssetID}
}

const assetPipelineTopicPrefix = "pipeline."

// AssetPipelinePayload is the payload of every asset pipeline step job.
// The asset is the only argument - jobs are unique by their arguments, therefore an asset has at most one queued or running job per step.
// Every step enqueues the following step once it succeeded.
type AssetPipelinePayload struct {
	AssetID uuid.UUID `json:"assetId"`
}

func (p AssetPipelinePayload) AlertContext() monitoring.AlertContext {
	return monitoring.AlertContext{AssetID: p.AssetID}
}

func notify(ctx context.Context, broker Broker, topic NotifyTopic, payload any) {
	if err := broker.Notify(ctx, nil, topic, payload, nil); err != nil {
		slog.Error("could not notify event", "topic", topic, "err", err)
	}
}

// NotifySBOMCreatedWithVulns - an sbom of the artifact was created or changed and scanned, the scan opened the vulns
func NotifySBOMCreatedWithVulns(ctx context.Context, broker Broker, artifact ArtifactPayload, vulnIDs []uuid.UUID) {
	notify(ctx, broker, TopicSBOMCreated, artifact)
	if len(vulnIDs) == 0 {
		return
	}
	artifact.VulnIDs = vulnIDs
	notify(ctx, broker, TopicDependencyVulnsDetected, artifact)
}

// NotifyDependencyVulnsDetected - a scan of the artifact opened the vulns
func NotifyDependencyVulnsDetected(ctx context.Context, broker Broker, artifact ArtifactPayload, vulnIDs []uuid.UUID) {
	if len(vulnIDs) == 0 {
		return
	}
	artifact.VulnIDs = vulnIDs
	notify(ctx, broker, TopicDependencyVulnsDetected, artifact)
}

// NotifyArtifactDeleted - an artifact of the asset was deleted
func NotifyArtifactDeleted(ctx context.Context, broker Broker, assetID uuid.UUID) {
	notify(ctx, broker, TopicArtifactDeleted, AssetPayload{AssetID: assetID})
}

// NotifyFirstPartyScanned - first party scan results of the asset version were stored, the scan opened the vulns
func NotifyFirstPartyScanned(ctx context.Context, broker Broker, assetVersion ArtifactPayload, openedVulnIDs []uuid.UUID) {
	assetVersion.VulnIDs = openedVulnIDs
	notify(ctx, broker, TopicFirstPartyScanned, assetVersion)
}

// NotifyAssetVersionDeleted - asset versions of the asset were deleted
func NotifyAssetVersionDeleted(ctx context.Context, broker Broker, assetID uuid.UUID) {
	notify(ctx, broker, TopicAssetVersionDeleted, AssetPayload{AssetID: assetID})
}

// NotifyVEXRuleCreated - a vex rule of the asset was created and applied
func NotifyVEXRuleCreated(ctx context.Context, broker Broker, assetID uuid.UUID) {
	notify(ctx, broker, TopicVEXRuleCreated, AssetPayload{AssetID: assetID})
}

// NotifyVEXRuleDeleted - a vex rule of the asset was deleted and the vulns it covered were reopened
func NotifyVEXRuleDeleted(ctx context.Context, broker Broker, assetID uuid.UUID) {
	notify(ctx, broker, TopicVEXRuleDeleted, AssetPayload{AssetID: assetID})
}

// NotifyAssetTicketSettingsChanged - the ticket thresholds or the ticket range of the asset changed
func NotifyAssetTicketSettingsChanged(ctx context.Context, broker Broker, assetID uuid.UUID) {
	notify(ctx, broker, TopicAssetTicketSettingsChanged, AssetPayload{AssetID: assetID})
}

// NotifyVulnEventCreated - a vuln of the asset received an event. If the event changes the risk, the statistics are recalculated right away
func NotifyVulnEventCreated(ctx context.Context, broker Broker, assetID uuid.UUID, eventType dtos.VulnEventType) {
	switch eventType {
	case dtos.EventTypeAccepted, dtos.EventTypeFalsePositive, dtos.EventTypeReopened:
		if err := broker.Notify(ctx, nil, TopicPipelineCollectStats, AssetPipelinePayload{AssetID: assetID}, nil); err != nil {
			slog.Error("could not enqueue stats collection", "assetID", assetID, "err", err)
		}
	}
}
