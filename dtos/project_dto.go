// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package dtos

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type ProjectCreateRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`

	ParentID *uuid.UUID `json:"parentId"` // if created as a child project
	Type     string     `json:"type"`
}

type ProjectChangeRoleRequest struct {
	Role string `json:"role" validate:"required,oneof=member admin"`
}

type ProjectInviteRequest struct {
	Ids []string `json:"ids" validate:"required"`
}

type ProjectPatchRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	IsPublic    *bool   `json:"isPublic"`

	Type *string `json:"type"`

	RepositoryID   *string         `json:"repositoryId"`
	RepositoryName *string         `json:"repositoryName"`
	ConfigFiles    *map[string]any `json:"configFiles"`
}

type ProjectDTO struct {
	Avatar      *string   `json:"avatar,omitempty"` // URL to the project's avatar
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	IsPublic    bool      `json:"isPublic"`
	Type        string    `json:"type"`

	ParentID *uuid.UUID  `json:"parentId"`
	Parent   *ProjectDTO `json:"parent,omitempty"` // recursive structure

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	Assets      []AssetDTO     `json:"assets"`
	ConfigFiles map[string]any `json:"configFiles"`

	ExternalEntityProviderID *string `json:"externalEntityProviderId,omitempty"`
	ExternalEntityID         *string `json:"externalEntityId,omitempty"` // only set if this is an external entity

	SubGroupsAndAssets []ProjectAssetDTO `json:"subGroupsAndAsset"`
}

type ProjectDetailsDTO struct {
	ProjectDTO
	Members  []UserDTO               `json:"members"`
	Webhooks []WebhookIntegrationDTO `json:"webhooks"`
}

type ProjectAssetDTO struct {
	ResourceType string     `json:"resourceType"` // "project" or "asset"
	ID           uuid.UUID  `json:"id"`
	Avatar       *string    `json:"avatar,omitempty"` // URL to the asset's avatar
	Name         string     `json:"name"`
	Slug         string     `json:"slug"`
	Description  string     `json:"description"`
	ProjectID    uuid.UUID  `json:"projectId"`
	ParentID     *uuid.UUID `json:"parentId,omitempty"` // only set for projects, not for assets
	IsPublic     bool       `json:"isPublic"`
	State        string     `json:"state"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`

	SubGroupsAndAssets []ProjectAssetDTO `json:"subGroupsAndAsset" gorm:"-"`
}

type ProjectsAssetAssetVersionsDTO struct {
	ProjectExternalEntityID string `json:"projectExternalEntityId"`
	ProjectName             string `json:"projectName"`
	SubProjects             []struct {
		SubProjectExternalEntityID string `json:"subProjectExternalEntityId,omitempty"`
		SubProjectName             string `json:"subProjectName,omitempty"`
		SubProjectDescription      string `json:"subProjectDescription,omitempty"`
		Assets                     []struct {
			AssetExternalEntityID string `json:"assetExternalEntityId"`
			AssetName             string `json:"assetName"`
			AssetVersions         []struct {
				AssetVersionName string   `json:"assetVersionName"`
				Artifacts        []string `json:"artifacts"`
			} `json:"assetVersions"`
		} `json:"assets"`
	} `json:"subProjects,omitempty"`
	Assets []struct {
		AssetExternalEntityID string `json:"assetExternalEntityId"`
		AssetName             string `json:"assetName"`
		AssetVersions         []struct {
			AssetVersionName string   `json:"assetVersionName"`
			Artifacts        []string `json:"artifacts"`
		} `json:"assetVersions"`
	} `json:"assets"`
}
type ExternalSubprojectRequestDTO struct {
	Verb                       string          `json:"verb" validate:"required,oneof=update delete"`
	ProjectExternalEntityID    string          `json:"projectExternalEntityId" validate:"required"`
	ProjectName                string          `json:"projectName"`
	ProjectDescription         string          `json:"projectDescription"`
	SubProjectExternalEntityID string          `json:"subProjectExternalEntityId,omitempty"`
	SubProjectName             string          `json:"subProjectName,omitempty"`
	SubProjectDescription      string          `json:"subProjectDescription,omitempty"`
	AssetExternalEntityID      string          `json:"assetExternalEntityId" validate:"required"`
	AssetName                  string          `json:"assetName"`
	AssetDescription           string          `json:"assetDescription"`
	AssetVersionName           string          `json:"assetVersionName"`
	Artifact                   string          `json:"artifact"`
	Sbom                       json.RawMessage `json:"sbom,omitempty"`
}
