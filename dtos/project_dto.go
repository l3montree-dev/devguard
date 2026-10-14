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
	Name        string `json:"name" validate:"required,max=256"`
	Description string `json:"description" validate:"max=4000"`

	ParentID *uuid.UUID `json:"parentId"` // if created as a child project
	Type     string     `json:"type" validate:"max=256"`
}

type ProjectChangeRoleRequest struct {
	Role string `json:"role" validate:"required,oneof=member admin"`
}

type ProjectInviteRequest struct {
	Ids []string `json:"ids" validate:"required,max=100,dive,max=256"`
}

type ProjectPatchRequest struct {
	Name        *string `json:"name" validate:"omitempty,max=256"`
	Description *string `json:"description" validate:"omitempty,max=4000"`
	IsPublic    *bool   `json:"isPublic"`

	Type *string `json:"type" validate:"omitempty,max=256"`

	RepositoryID   *string         `json:"repositoryId" validate:"omitempty,max=256"`
	RepositoryName *string         `json:"repositoryName" validate:"omitempty,max=256"`
	ConfigFiles    *map[string]any `json:"configFiles"`
}

type Project struct {
	Avatar      *string   `json:"avatar,omitempty"` // URL to the project's avatar
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	IsPublic    bool      `json:"isPublic"`
	Type        string    `json:"type"`

	ParentID *uuid.UUID `json:"parentId"`
	Parent   *Project   `json:"parent,omitempty"` // recursive structure

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	Assets      []Asset        `json:"assets"`
	ConfigFiles map[string]any `json:"configFiles"`

	ExternalEntityProviderID *string `json:"externalEntityProviderId,omitempty"`
	ExternalEntityID         *string `json:"externalEntityId,omitempty"` // only set if this is an external entity

	SubGroupsAndAssets []ProjectAsset `json:"subGroupsAndAsset"`
}

type ProjectDetails struct {
	Project
	Members  []User               `json:"members"`
	Webhooks []WebhookIntegration `json:"webhooks"`
}

type ProjectAsset struct {
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

	SubGroupsAndAssets []ProjectAsset `json:"subGroupsAndAsset" gorm:"-"`
}

type AssetVersionEntry struct {
	AssetVersionName string   `json:"assetVersionName"`
	Artifacts        []string `json:"artifacts"`
}

type AssetEntry struct {
	AssetExternalEntityID string              `json:"assetExternalEntityId"`
	AssetName             string              `json:"assetName"`
	AssetVersions         []AssetVersionEntry `json:"assetVersions"`
}

type SubProjectEntry struct {
	SubProjectExternalEntityID string       `json:"subProjectExternalEntityId,omitempty"`
	SubProjectName             string       `json:"subProjectName,omitempty"`
	SubProjectDescription      string       `json:"subProjectDescription,omitempty"`
	Assets                     []AssetEntry `json:"assets"`
}

type ProjectExternalEntityTree struct {
	ProjectExternalEntityID string            `json:"projectExternalEntityId"`
	ProjectName             string            `json:"projectName"`
	SubProjects             []SubProjectEntry `json:"subProjects,omitempty"`
	Assets                  []AssetEntry      `json:"assets"`
}
type ExternalSubprojectRequest struct {
	Verb                       string          `json:"verb" validate:"required,oneof=update delete"`
	ProjectExternalEntityID    string          `json:"projectExternalEntityId" validate:"required,max=256"`
	ProjectName                string          `json:"projectName" validate:"max=256"`
	ProjectDescription         string          `json:"projectDescription" validate:"max=4000"`
	SubProjectExternalEntityID string          `json:"subProjectExternalEntityId,omitempty" validate:"max=256"`
	SubProjectName             string          `json:"subProjectName,omitempty" validate:"max=256"`
	SubProjectDescription      string          `json:"subProjectDescription,omitempty" validate:"max=4000"`
	AssetExternalEntityID      string          `json:"assetExternalEntityId" validate:"required,max=256"`
	AssetName                  string          `json:"assetName" validate:"max=256"`
	AssetDescription           string          `json:"assetDescription" validate:"max=4000"`
	AssetVersionName           string          `json:"assetVersionName" validate:"max=256"`
	Artifact                   string          `json:"artifact" validate:"max=256"`
	Sbom                       json.RawMessage `json:"sbom,omitempty"`
}
