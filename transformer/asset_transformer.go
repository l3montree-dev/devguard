// Copyright (C) 2025 l3montree GmbH
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

package transformer

import (
	"github.com/google/uuid"
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

func AssetModelsToDTOs(assets []models.Asset) []dtos.AssetDTO {
	assetDTOs := make([]dtos.AssetDTO, len(assets))
	for i, asset := range assets {
		assetDTOs[i] = AssetModelToDTO(asset)
	}
	return assetDTOs
}

func AssetModelToDetailsDTO(asset models.Asset, members []dtos.UserDTO) dtos.AssetDetailsDTO {
	return dtos.AssetDetailsDTO{
		AssetDTO: AssetModelToDTO(asset),
		Members:  members,
	}
}

func AssetModelToDetailsWithSecretsDTO(asset models.Asset, members []dtos.UserDTO) dtos.AssetDetailsWithSecretsDTO {
	return dtos.AssetDetailsWithSecretsDTO{
		AssetWithSecretsDTO: toDTOWithSecrets(asset),
		Members:             members,
	}
}

func AssetModelToDTO(asset models.Asset) dtos.AssetDTO {
	return dtos.AssetDTO{
		ID:                            asset.ID,
		Name:                          asset.Name,
		Avatar:                        asset.Avatar,
		Slug:                          asset.Slug,
		Description:                   asset.Description,
		ProjectID:                     asset.ProjectID,
		AvailabilityRequirement:       asset.AvailabilityRequirement,
		IntegrityRequirement:          asset.IntegrityRequirement,
		ConfidentialityRequirement:    asset.ConfidentialityRequirement,
		ReachableFromInternet:         asset.ReachableFromInternet,
		RepositoryID:                  asset.RepositoryID,
		RepositoryName:                asset.RepositoryName,
		SigningPubKey:                 asset.SigningPubKey,
		CVSSAutomaticTicketThreshold:  asset.CVSSAutomaticTicketThreshold,
		RiskAutomaticTicketThreshold:  asset.RiskAutomaticTicketThreshold,
		VulnAutoReopenAfterDays:       asset.VulnAutoReopenAfterDays,
		AssetVersions:                 utils.Map(asset.AssetVersions, AssetVersionModelToDTO),
		ExternalEntityProviderID:      asset.ExternalEntityProviderID,
		ExternalEntityID:              asset.ExternalEntityID,
		RepositoryProvider:            asset.RepositoryProvider,
		IsPublic:                      asset.IsPublic,
		ParanoidMode:                  asset.ParanoidMode,
		SharesInformation:             asset.SharesInformation,
		KeepOriginalSbomRootComponent: asset.KeepOriginalSbomRootComponent,
		PipelineLastRun:               asset.PipelineLastRun,
		PipelineError:                 asset.PipelineError,
		Archived:                      asset.Archived,
	}
}

func toDTOWithSecrets(asset models.Asset) dtos.AssetWithSecretsDTO {
	return dtos.AssetWithSecretsDTO{
		AssetDTO:      AssetModelToDTO(asset),
		WebhookSecret: asset.WebhookSecret,
	}
}

func AssetCreateRequestToModel(assetCreateRequest dtos.AssetCreateRequest, projectID uuid.UUID) models.Asset {
	asset := models.Asset{Name: assetCreateRequest.Name,
		Slug:        slug.Make(assetCreateRequest.Name),
		ProjectID:   projectID,
		Description: assetCreateRequest.Description,

		Importance:            assetCreateRequest.Importance,
		ReachableFromInternet: assetCreateRequest.ReachableFromInternet,

		ConfidentialityRequirement: sanitizeRequirementLevel(assetCreateRequest.ConfidentialityRequirement),
		IntegrityRequirement:       sanitizeRequirementLevel(assetCreateRequest.IntegrityRequirement),
		AvailabilityRequirement:    sanitizeRequirementLevel(assetCreateRequest.AvailabilityRequirement),
		RepositoryProvider:         assetCreateRequest.RepositoryProvider,
	}

	if assetCreateRequest.EnableTicketRange {
		asset.CVSSAutomaticTicketThreshold = assetCreateRequest.CVSSAutomaticTicketThreshold
		asset.RiskAutomaticTicketThreshold = assetCreateRequest.RiskAutomaticTicketThreshold
	}

	return asset
}

func sanitizeRequirementLevel(level string) dtos.RequirementLevel {
	switch level {
	case "low", "medium", "high":
		return dtos.RequirementLevel(level)
	default:
		return "medium"
	}
}

func ApplyAssetPatchRequestToModel(assetPatch dtos.AssetPatchRequest, asset *models.Asset) bool {
	updated := false
	if assetPatch.Name != nil {
		updated = true
		asset.Name = *assetPatch.Name
		asset.Slug = slug.Make(*assetPatch.Name)
	}

	if assetPatch.SharesInformation != nil {
		updated = true
		asset.SharesInformation = *assetPatch.SharesInformation
	}

	if assetPatch.KeepOriginalSbomRootComponent != nil {
		updated = true
		asset.KeepOriginalSbomRootComponent = *assetPatch.KeepOriginalSbomRootComponent
	}

	if assetPatch.Description != nil {
		updated = true
		asset.Description = *assetPatch.Description
	}

	if assetPatch.ReachableFromInternet != nil {
		updated = true
		asset.ReachableFromInternet = *assetPatch.ReachableFromInternet
	}

	if assetPatch.RepositoryID != nil {
		updated = true
		if *assetPatch.RepositoryID == "" {
			asset.RepositoryID = nil
		} else {
			asset.RepositoryID = assetPatch.RepositoryID
		}
	}

	if assetPatch.RepositoryName != nil {
		updated = true
		if *assetPatch.RepositoryName == "" {
			asset.RepositoryName = nil
		} else {
			asset.RepositoryName = assetPatch.RepositoryName
		}
	}

	if assetPatch.ConfigFiles != nil {
		updated = true
		asset.ConfigFiles = *assetPatch.ConfigFiles
	}

	if assetPatch.WebhookSecret != nil {
		updated = true

		if *assetPatch.WebhookSecret == "" {
			asset.WebhookSecret = nil
		}

		webhookUUID, err := uuid.Parse(*assetPatch.WebhookSecret)
		if err == nil {
			asset.WebhookSecret = &webhookUUID

		}
	}

	if assetPatch.VulnAutoReopenAfterDays != nil {
		updated = true
		asset.VulnAutoReopenAfterDays = assetPatch.VulnAutoReopenAfterDays
	}

	if assetPatch.RepositoryProvider != nil && *assetPatch.RepositoryProvider != "" {
		updated = true
		if *assetPatch.RepositoryProvider == "" {
			asset.RepositoryProvider = nil
		} else {
			asset.RepositoryProvider = assetPatch.RepositoryProvider
		}
	}

	if assetPatch.IsPublic != nil {
		updated = true
		asset.IsPublic = *assetPatch.IsPublic
	}

	if assetPatch.ParanoidMode != nil {
		updated = true
		asset.ParanoidMode = *assetPatch.ParanoidMode
	}

	return updated
}
