// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package listeners

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/events"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
)

// the listeners react to the domain events, see events.TopicSBOMCreated and the others.
// most of them only enqueue pipeline steps - the integration webhooks are the only work done right in the listener.
// all listeners of a topic run in the same job and are retried together.

// enqueueStep enqueues the pipeline step for the asset of the event - the following steps run afterwards
func (runner *DaemonRunner) enqueueStep(step events.NotifyTopic) events.NotifyHandler {
	return job("could not enqueue "+string(step), func(ctx context.Context, payload events.AssetPayload) error {
		return runner.broker.Notify(ctx, nil, step, events.AssetPipelinePayload{AssetID: payload.AssetID}, nil)
	})
}

// enqueueCleanup enqueues the orphan cleanup - bursts of deletions collapse into a single job
func (runner *DaemonRunner) enqueueCleanup() events.NotifyHandler {
	return job("could not enqueue the orphan cleanup", func(ctx context.Context, _ events.EmptyPayload) error {
		return runner.broker.Notify(ctx, nil, events.TopicCleanupOrphanedRecords, nil, nil)
	})
}

type artifactWithDetails struct {
	org          models.Org
	project      models.Project
	asset        models.Asset
	assetVersion models.AssetVersion
	artifactName string
	userAgent    string
	vulnIDs      []uuid.UUID
}

// artifactJob loads the artifact of the payload and runs fn on it
func (runner *DaemonRunner) artifactJob(errMsg string, fn func(ctx context.Context, artifact artifactWithDetails) error) events.NotifyHandler {
	return job(errMsg, func(ctx context.Context, payload events.ArtifactPayload) error {
		artifact, err := runner.fetchArtifactDetails(ctx, payload)
		if err != nil {
			return err
		}
		return fn(ctx, artifact)
	})
}

func (runner *DaemonRunner) fetchArtifactDetails(ctx context.Context, payload events.ArtifactPayload) (artifactWithDetails, error) {
	asset, err := runner.assetRepository.Read(ctx, nil, payload.AssetID)
	if err != nil {
		return artifactWithDetails{}, fmt.Errorf("could not fetch asset: %w", err)
	}
	assetVersion, err := runner.assetVersionRepository.Read(ctx, nil, payload.AssetVersionName, payload.AssetID)
	if err != nil {
		return artifactWithDetails{}, fmt.Errorf("could not fetch asset version: %w", err)
	}
	project, err := runner.projectRepository.Read(ctx, nil, asset.ProjectID)
	if err != nil {
		return artifactWithDetails{}, fmt.Errorf("could not fetch project: %w", err)
	}
	org, err := runner.orgRepository.Read(ctx, nil, project.OrganizationID)
	if err != nil {
		return artifactWithDetails{}, fmt.Errorf("could not fetch org: %w", err)
	}
	return artifactWithDetails{
		org:          org,
		project:      project,
		asset:        asset,
		assetVersion: assetVersion,
		artifactName: payload.ArtifactName,
		userAgent:    payload.UserAgent,
		vulnIDs:      payload.VulnIDs,
	}, nil
}

// the integrations are only told about default branches and tags
func (a artifactWithDetails) notifiesIntegrations() bool {
	return a.assetVersion.DefaultBranch || a.assetVersion.Type == models.AssetVersionTag
}

// sendSBOMCreatedEvent exports the current sboms of the artifact and hands them to the integrations
func (runner *DaemonRunner) sendSBOMCreatedEvent(ctx context.Context, a artifactWithDetails) error {
	if !a.notifiesIntegrations() {
		return nil
	}
	forest, err := runner.assetVersionService.LoadArtifactSBOMs(ctx, nil, a.assetVersion, a.artifactName)
	if err != nil {
		return err
	}
	metadata, err := runner.assetVersionService.LoadComponentMetadata(ctx, nil, a.assetVersion, forest)
	if err != nil {
		return fmt.Errorf("could not load component metadata: %w", err)
	}
	return runner.integrationAggregate.HandleEvent(ctx, shared.SBOMCreatedEvent{
		AssetVersion: shared.ToAssetVersionObject(a.assetVersion),
		Asset:        shared.ToAssetObject(a.asset),
		Project:      shared.ToProjectObject(a.project),
		Org:          shared.ToOrgObject(a.org),
		Artifact:     shared.ArtifactObject{ArtifactName: a.artifactName},
		SBOM:         transformer.ForestToCycloneDX(forest, normalize.BOMMetadata{RootName: a.artifactName}, metadata),
	}, &a.userAgent)
}

// sendDependencyVulnsDetectedEvent hands the vulns a scan opened to the integrations
func (runner *DaemonRunner) sendDependencyVulnsDetectedEvent(ctx context.Context, a artifactWithDetails) error {
	if !a.notifiesIntegrations() || len(a.vulnIDs) == 0 {
		return nil
	}
	var vulns []models.DependencyVuln
	if err := runner.db.WithContext(ctx).Preload("CVE").Preload("CVE.Exploits").Find(&vulns, a.vulnIDs).Error; err != nil {
		return fmt.Errorf("could not fetch detected vulns: %w", err)
	}
	if len(vulns) == 0 {
		return nil
	}
	return runner.integrationAggregate.HandleEvent(ctx, shared.DependencyVulnsDetectedEvent{
		AssetVersion: shared.ToAssetVersionObject(a.assetVersion),
		Asset:        shared.ToAssetObject(a.asset),
		Project:      shared.ToProjectObject(a.project),
		Org:          shared.ToOrgObject(a.org),
		Vulns:        utils.Map(vulns, transformer.DependencyVulnToDTO),
		Artifact:     shared.ArtifactObject{ArtifactName: a.artifactName},
	}, &a.userAgent)
}

// sendFirstPartyVulnsDetectedEvent hands the first party vulns a scan opened to the integrations
func (runner *DaemonRunner) sendFirstPartyVulnsDetectedEvent(ctx context.Context, a artifactWithDetails) error {
	if !a.notifiesIntegrations() || len(a.vulnIDs) == 0 {
		return nil
	}
	var vulns []models.FirstPartyVuln
	if err := runner.db.WithContext(ctx).Find(&vulns, a.vulnIDs).Error; err != nil {
		return fmt.Errorf("could not fetch detected first party vulns: %w", err)
	}
	if len(vulns) == 0 {
		return nil
	}
	return runner.integrationAggregate.HandleEvent(ctx, shared.FirstPartyVulnsDetectedEvent{
		AssetVersion: shared.ToAssetVersionObject(a.assetVersion),
		Asset:        shared.ToAssetObject(a.asset),
		Project:      shared.ToProjectObject(a.project),
		Org:          shared.ToOrgObject(a.org),
		Vulns:        utils.Map(vulns, transformer.FirstPartyVulnToDto),
	}, &a.userAgent)
}
