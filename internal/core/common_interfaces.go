// Copyright (C) 2025 timbastin
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

package core

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type ProjectRepository interface {
	ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error)
	ReadBySlugUnscoped(organizationId uuid.UUID, slug string) (models.Project, error)
	Update(tx DB, project *models.Project) error
	Delete(tx DB, projectID uuid.UUID) error
	Create(tx DB, project *models.Project) error
	Activate(tx DB, projectID uuid.UUID) error
	RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error)
	GetDirectChildProjects(projectID uuid.UUID) ([]models.Project, error)
	GetByOrgID(organizationID uuid.UUID) ([]models.Project, error)
	GetProjectByAssetID(assetID uuid.UUID) (models.Project, error)
	List(idSlice []uuid.UUID, parentID *uuid.UUID, tenantID uuid.UUID) ([]models.Project, error)
}

type AssetRepository interface {
	common.Repository[uuid.UUID, models.Asset, DB]
	GetByProjectID(projectID uuid.UUID) ([]models.Asset, error)
	FindByName(name string) (models.Asset, error)
	FindOrCreate(tx DB, name string) (models.Asset, error)
	ReadBySlug(projectID uuid.UUID, slug string) (models.Asset, error)
	GetAssetIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error)
	Update(tx DB, asset *models.Asset) error
	ReadBySlugUnscoped(projectID uuid.UUID, slug string) (models.Asset, error)
}

type CveRepository interface {
	common.Repository[string, models.CVE, database.DB]
	FindByID(id string) (models.CVE, error)
	GetLastModDate() (time.Time, error)
	SaveBatchCPEMatch(tx database.DB, matches []models.CPEMatch) error
	GetAllCVEsID() ([]string, error)
	GetAllCPEMatchesID() ([]string, error)
	Save(tx database.DB, cve *models.CVE) error
	SaveCveAffectedComponents(tx DB, cveId string, affectedComponentHashes []string) error
}

type CweRepository interface {
	GetAllCWEsID() ([]string, error)
	SaveBatch(tx database.DB, cwes []models.CWE) error
}

type ExploitRepository interface {
	GetAllExploitsID() ([]string, error)
	SaveBatch(tx DB, exploits []models.Exploit) error
}

type AffectedComponentRepository interface {
	GetAllAffectedComponentsID() ([]string, error)
	Save(tx DB, affectedComponent *models.AffectedComponent) error
	SaveBatch(tx DB, affectedPkgs []models.AffectedComponent) error
}

type DependencyVulnRepository interface {
	common.Repository[string, models.DependencyVuln, DB]

	GetDependencyVulnsByAssetVersion(tx DB, assetVersionName string, assetVersionID uuid.UUID) ([]models.DependencyVuln, error)
	GetByAssetVersionPaged(tx DB, assetVersionName string, assetID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], map[string]int, error)
	GetDefaultDependencyVulnsByOrgIdPaged(tx DB, userAllowedProjectIds []string, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)
	GetDefaultDependencyVulnsByProjectIdPaged(tx DB, projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)
	GetDependencyVulnsByAssetVersionPagedAndFlat(tx DB, assetVersionName string, assetVersionID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)

	ReadDependencyVulnWithAssetVersionEvents(id string) (models.DependencyVuln, []models.VulnEvent, error)
}

type FirstPartyVulnRepository interface {
	common.Repository[string, models.FirstPartyVulnerability, DB]
	SaveBatch(tx DB, vulns []models.FirstPartyVulnerability) error
	Save(tx DB, vuln *models.FirstPartyVulnerability) error
	Transaction(txFunc func(DB) error) error
	Begin() DB
	GetDefaultFirstPartyVulnsByProjectIdPaged(tx DB, projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVulnerability], error)
	GetDefaultFirstPartyVulnsByOrgIdPaged(tx DB, userAllowedProjectIds []string, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVulnerability], error)
	GetFirstPartyVulnsByAssetIdPagedAndFlat(tx DB, assetVersionName string, assetID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVulnerability], error)

	GetByAssetId(tx DB, assetId uuid.UUID) ([]models.FirstPartyVulnerability, error)
	GetByAssetVersionPaged(tx DB, assetVersionName string, assetID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVulnerability], map[string]int, error)
}

type InTotoLinkRepository interface {
	common.Repository[uuid.UUID, models.InTotoLink, DB]
	FindByAssetAndSupplyChainId(assetID uuid.UUID, supplyChainId string) ([]models.InTotoLink, error)
	Save(tx DB, model *models.InTotoLink) error
	FindBySupplyChainID(supplyChainID string) ([]models.InTotoLink, error)
}

type PersonalAccessTokenRepository interface {
	common.Repository[uuid.UUID, models.PAT, DB]
	GetByFingerprint(fingerprint string) (models.PAT, error)
	FindByUserIDs(userID []uuid.UUID) ([]models.PAT, error)
	ListByUserID(userID string) ([]models.PAT, error)
	DeleteByFingerprint(fingerprint string) error
	MarkAsLastUsedNow(fingerprint string) error
}

type SupplyChainRepository interface {
	common.Repository[uuid.UUID, models.SupplyChain, DB]
	FindByDigest(digest string) ([]models.SupplyChain, error)
	FindBySupplyChainID(supplyChainID string) ([]models.SupplyChain, error)
}

type OrganizationRepository interface {
	common.Repository[uuid.UUID, models.Org, DB]
	ReadBySlug(slug string) (models.Org, error)
	Update(tx DB, organization *models.Org) error
	ContentTree(orgID uuid.UUID, projects []string) []common.ContentTreeElement
}

type InvitationRepository interface {
	Save(tx DB, invitation *models.Invitation) error
	FindByCode(code string) (models.Invitation, error)
	Delete(tx DB, id uuid.UUID) error
}
