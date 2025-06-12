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
	"context"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm/clause"
)

type SBOMScanner interface {
	Scan(bom normalize.SBOM) ([]models.VulnInPackage, error)
}
type ProjectRepository interface {
	Read(projectID uuid.UUID) (models.Project, error)
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
	List(idSlice []uuid.UUID, parentID *uuid.UUID, organizationID uuid.UUID) ([]models.Project, error)
	EnablePolicyForProject(tx DB, projectID uuid.UUID, policyID uuid.UUID) error
	DisablePolicyForProject(tx DB, projectID uuid.UUID, policyID uuid.UUID) error
	Upsert(projects *[]*models.Project, conflictingColumns []clause.Column, toUpdate []string) error
	EnableCommunityManagedPolicies(tx DB, projectID uuid.UUID) error
	UpsertSplit(tx DB, externalProviderID string, projects []*models.Project) ([]*models.Project, []*models.Project, error)
}

type PolicyRepository interface {
	common.Repository[uuid.UUID, models.Policy, DB]
	FindByProjectId(projectId uuid.UUID) ([]models.Policy, error)
	FindByOrganizationId(organizationId uuid.UUID) ([]models.Policy, error)
	FindCommunityManagedPolicies() ([]models.Policy, error)
}

type AssetRepository interface {
	common.Repository[uuid.UUID, models.Asset, DB]
	GetByProjectID(projectID uuid.UUID) ([]models.Asset, error)
	GetByOrgID(organizationID uuid.UUID) ([]models.Asset, error)
	FindByName(name string) (models.Asset, error)
	FindAssetByExternalProviderId(externalEntityProviderID string, externalEntityID string) (*models.Asset, error)
	GetFQNByID(id uuid.UUID) (string, error)
	FindOrCreate(tx DB, name string) (models.Asset, error)
	ReadBySlug(projectID uuid.UUID, slug string) (models.Asset, error)
	GetAssetIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error)
	Update(tx DB, asset *models.Asset) error
	ReadBySlugUnscoped(projectID uuid.UUID, slug string) (models.Asset, error)
	GetAllAssetsFromDB() ([]models.Asset, error)
	Delete(tx DB, id uuid.UUID) error
	GetAssetIDByBadgeSecret(badgeSecret uuid.UUID) (models.Asset, error)
	ReadWithAssetVersions(assetID uuid.UUID) (models.Asset, error)
}

type AttestationRepository interface {
	common.Repository[string, models.Attestation, DB]
	GetByAssetID(assetID uuid.UUID) ([]models.Attestation, error)
	GetByAssetVersionAndAssetID(assetID uuid.UUID, assetVersion string) ([]models.Attestation, error)
}

type CveRepository interface {
	common.Repository[string, models.CVE, DB]
	FindByID(id string) (models.CVE, error)
	GetLastModDate() (time.Time, error)
	SaveBatchCPEMatch(tx DB, matches []models.CPEMatch) error
	GetAllCVEsID() ([]string, error)
	GetAllCPEMatchesID() ([]string, error)
	Save(tx DB, cve *models.CVE) error
	SaveCveAffectedComponents(tx DB, cveId string, affectedComponentHashes []string) error
	FindCVE(tx DB, id string) (models.CVE, error)
	FindCVEs(tx DB, ids []string) ([]models.CVE, error)
	FindAllListPaged(tx DB, pageInfo PageInfo, filter []FilterQuery, sort []SortQuery) (Paged[models.CVE], error)
}

type CweRepository interface {
	GetAllCWEsID() ([]string, error)
	SaveBatch(tx DB, cwes []models.CWE) error
}

type ExploitRepository interface {
	GetAllExploitsID() ([]string, error)
	SaveBatch(tx DB, exploits []models.Exploit) error
}

type AffectedComponentRepository interface {
	GetAllAffectedComponentsID() ([]string, error)
	Save(tx DB, affectedComponent *models.AffectedComponent) error
	SaveBatch(tx DB, affectedPkgs []models.AffectedComponent) error
	DeleteAll(tx DB, ecosystem string) error
}

type ComponentRepository interface {
	common.Repository[string, models.Component, DB]

	LoadComponents(tx DB, assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.ComponentDependency, error)
	LoadComponentsWithProject(tx DB, overwrittenLicenses []models.LicenseOverwrite, assetVersionName string, assetID uuid.UUID, scannerID string, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.ComponentDependency], error)
	LoadPathToComponent(tx DB, assetVersionName string, assetID uuid.UUID, pURL string, scannerID string) ([]models.ComponentDependency, error)
	SaveBatch(tx DB, components []models.Component) error
	FindByPurl(tx DB, purl string) (models.Component, error)
	HandleStateDiff(tx DB, assetVersionName string, assetID uuid.UUID, oldState []models.ComponentDependency, newState []models.ComponentDependency, scannerID string) error
	GetDependencyCountPerScanner(assetVersionName string, assetID uuid.UUID) (map[string]int, error)
	GetLicenseDistribution(tx DB, assetVersionName string, assetID uuid.UUID, scannerID string) (map[string]int, error)
}

type DependencyVulnRepository interface {
	common.Repository[string, models.DependencyVuln, DB]

	GetAllVulnsByAssetID(tx DB, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetAllOpenVulnsByAssetVersionNameAndAssetId(tx DB, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetDependencyVulnsByAssetVersion(tx DB, assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.DependencyVuln, error)
	GetByAssetVersionPaged(tx DB, assetVersionName string, assetID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], map[string]int, error)
	GetDefaultDependencyVulnsByOrgIdPaged(tx DB, userAllowedProjectIds []string, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)
	GetDefaultDependencyVulnsByProjectIdPaged(tx DB, projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)
	GetDependencyVulnsByAssetVersionPagedAndFlat(tx DB, assetVersionName string, assetVersionID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)
	ListByAssetAndAssetVersion(assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetDependencyVulnsByPurl(tx DB, purls []string) ([]models.DependencyVuln, error)
	ApplyAndSave(tx DB, dependencyVuln *models.DependencyVuln, vulnEvent *models.VulnEvent) error
	GetDependencyVulnsByDefaultAssetVersion(tx DB, assetID uuid.UUID, scannerID string) ([]models.DependencyVuln, error)
	ListUnfixedByAssetAndAssetVersionAndScannerID(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.DependencyVuln, error)
}

type FirstPartyVulnRepository interface {
	common.Repository[string, models.FirstPartyVuln, DB]
	SaveBatch(tx DB, vulns []models.FirstPartyVuln) error
	Save(tx DB, vuln *models.FirstPartyVuln) error
	Transaction(txFunc func(DB) error) error
	Begin() DB
	GetDefaultFirstPartyVulnsByProjectIdPaged(tx DB, projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVuln], error)
	GetDefaultFirstPartyVulnsByOrgIdPaged(tx DB, userAllowedProjectIds []string, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVuln], error)
	GetByAssetId(tx DB, assetId uuid.UUID) ([]models.FirstPartyVuln, error)
	GetByAssetVersionPaged(tx DB, assetVersionName string, assetID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVuln], map[string]int, error)
	ListByScanner(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVuln, error)
	ApplyAndSave(tx DB, dependencyVuln *models.FirstPartyVuln, vulnEvent *models.VulnEvent) error
	GetByAssetVersion(tx DB, assetVersionName string, assetID uuid.UUID) ([]models.FirstPartyVuln, error)
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
	PercentageOfVerifiedSupplyChains(assetVersionName string, assetID uuid.UUID) (float64, error)
}

type OrganizationRepository interface {
	common.Repository[uuid.UUID, models.Org, DB]
	ReadBySlug(slug string) (models.Org, error)
	Update(tx DB, organization *models.Org) error
	ContentTree(orgID uuid.UUID, projects []string) []common.ContentTreeElement
	GetOrgByID(id uuid.UUID) (models.Org, error)
}

type OrgService interface {
	CreateOrganization(ctx Context, organization models.Org) error
	CreateExternalEntityOrganization(ctx Context, externalEntitySlug ExternalEntitySlug) (*models.Org, error)
	ReadBySlug(slug string) (*models.Org, error)
}

type InvitationRepository interface {
	Save(tx DB, invitation *models.Invitation) error
	FindByCode(code string) (models.Invitation, error)
	Delete(tx DB, id uuid.UUID) error
}

type ProjectService interface {
	ReadBySlug(ctx Context, organizationID uuid.UUID, slug string) (models.Project, error)
	ListAllowedProjects(ctx Context) ([]models.Project, error)
	ListProjectsByOrganizationID(organizationID uuid.UUID) ([]models.Project, error)
	RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error)
	GetDirectChildProjects(projectID uuid.UUID) ([]models.Project, error)
	CreateProject(ctx Context, project *models.Project) error
}

type InTotoVerifierService interface {
	VerifySupplyChainWithOutputDigest(supplyChainID string, digest string) (bool, error)
	VerifySupplyChain(supplyChainID string) (bool, error)
	VerifySupplyChainByDigestOnly(digest string) (bool, error)
}

type AssetService interface {
	UpdateAssetRequirements(asset models.Asset, responsible string, justification string) error
	GetCVSSBadgeSVG(CVSS models.AssetRiskDistribution) string
	CreateAsset(asset models.Asset) (*models.Asset, error)
}

type DependencyVulnService interface {
	RecalculateRawRiskAssessment(tx DB, responsible string, dependencyVulns []models.DependencyVuln, justification string, asset models.Asset) error
	UserFixedDependencyVulns(tx DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset) error
	UserDetectedDependencyVulns(tx DB, userID string, scannerID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset) error
	UserDetectedExistingVulnOnDifferentBranch(tx DB, userID, scannerID string, dependencyVulns []models.DependencyVuln, alreadyExistingEvents [][]models.VulnEvent, assetVersion models.AssetVersion, asset models.Asset) error
	UserDetectedDependencyVulnWithAnotherScanner(tx DB, vulnerabilities []models.DependencyVuln, userID string, scannerID string) error
	UserDidNotDetectDependencyVulnWithScannerAnymore(tx DB, vulnerabilities []models.DependencyVuln, userID string, scannerID string) error
	UpdateDependencyVulnState(tx DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, statusType string, justification string, mechanicalJustification models.MechanicalJustificationType, assetVersionName string) (models.VulnEvent, error)
	SyncIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, vulnList []models.DependencyVuln) error

	SyncAllIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion) error
}

// useful for integration testing - use in production to just fire and forget a function "go func()"
// during testing, this can be used to synchronize the execution of multiple goroutines - and wait for them to finish
type FireAndForgetSynchronizer interface {
	FireAndForget(fn func())
}

type AssetVersionService interface {
	BuildSBOM(assetVersion models.AssetVersion, version, orgName string, components []models.ComponentDependency) *cdx.BOM
	BuildVeX(asset models.Asset, assetVersion models.AssetVersion, orgName string, dependencyVulns []models.DependencyVuln) *cdx.BOM
	GetAssetVersionsByAssetID(assetID uuid.UUID) ([]models.AssetVersion, error)
	HandleFirstPartyVulnResult(asset models.Asset, assetVersion *models.AssetVersion, sarifScan common.SarifResult, scannerID string, userID string) (int, int, []models.FirstPartyVuln, error)
	UpdateSBOM(assetVersion models.AssetVersion, scannerID string, sbom normalize.SBOM) error
	HandleScanResult(asset models.Asset, assetVersion *models.AssetVersion, vulns []models.VulnInPackage, scannerID string, userID string) (opened []models.DependencyVuln, closed []models.DependencyVuln, newState []models.DependencyVuln, err error)
	BuildOpenVeX(asset models.Asset, assetVersion models.AssetVersion, organizationSlug string, dependencyVulns []models.DependencyVuln) vex.VEX
}

type AssetVersionRepository interface {
	All() ([]models.AssetVersion, error)
	Read(assetVersionName string, assetID uuid.UUID) (models.AssetVersion, error)
	GetDB(DB) DB
	Delete(tx DB, assetVersion *models.AssetVersion) error
	Save(tx DB, assetVersion *models.AssetVersion) error
	GetAllAssetsVersionFromDBByAssetID(tx DB, assetID uuid.UUID) ([]models.AssetVersion, error)
	GetDefaultAssetVersionsByProjectID(projectID uuid.UUID) ([]models.AssetVersion, error)
	GetDefaultAssetVersionsByProjectIDs(projectIDs []uuid.UUID) ([]models.AssetVersion, error)
	FindOrCreate(assetVersionName string, assetID uuid.UUID, tag bool, defaultBranchName *string) (models.AssetVersion, error)
	ReadBySlug(assetID uuid.UUID, slug string) (models.AssetVersion, error)
	GetDefaultAssetVersion(assetID uuid.UUID) (models.AssetVersion, error)
}

type FirstPartyVulnService interface {
	UserFixedFirstPartyVulns(tx DB, userID string, firstPartyVulns []models.FirstPartyVuln) error
	UserDetectedFirstPartyVulns(tx DB, userID string, scannerId string, firstPartyVulns []models.FirstPartyVuln) error
	UpdateFirstPartyVulnState(tx DB, userID string, firstPartyVuln *models.FirstPartyVuln, statusType string, justification string, mechanicalJustification models.MechanicalJustificationType) (models.VulnEvent, error)
}

type ConfigRepository interface {
	Save(tx DB, config *models.Config) error
	GetDB(tx DB) DB
}

type VulnEventRepository interface {
	SaveBatch(db DB, events []models.VulnEvent) error
	Save(db DB, event *models.VulnEvent) error
	ReadAssetEventsByVulnID(vulnID string, vulnType models.VulnType) ([]models.VulnEventDetail, error)
	ReadEventsByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string, pageInfo PageInfo, filter []FilterQuery) (Paged[models.VulnEventDetail], error)
}

type GithubAppInstallationRepository interface {
	Save(tx DB, model *models.GithubAppInstallation) error
	Read(installationID int) (models.GithubAppInstallation, error)
	FindByOrganizationId(orgID uuid.UUID) ([]models.GithubAppInstallation, error)
	Delete(tx DB, installationID int) error
}

type VulnRepository interface {
	FindByTicketID(tx DB, ticketID string) (models.Vuln, error)
	Save(db DB, vuln *models.Vuln) error
	Transaction(fn func(tx DB) error) error
	GetOrgFromVuln(vuln models.Vuln) (models.Org, error)
	ApplyAndSave(tx DB, dependencyVuln models.Vuln, vulnEvent *models.VulnEvent) error
}

type LicenseOverwriteRepository interface {
	common.Repository[string, models.LicenseOverwrite, DB]
	GetAllOverwritesForOrganization(orgID uuid.UUID) ([]models.LicenseOverwrite, error)
	MaybeGetOverwriteForComponent(orgID uuid.UUID, pURL packageurl.PackageURL) (models.LicenseOverwrite, error)
	DeleteByComponentPurlAndOrgID(orgID uuid.UUID, purl string) error
}

type ExternalUserRepository interface {
	Save(db DB, user *models.ExternalUser) error
	GetDB(tx DB) DB
	FindByOrgID(tx DB, orgID uuid.UUID) ([]models.ExternalUser, error)
}

type GitlabIntegrationRepository interface {
	Save(tx DB, model *models.GitLabIntegration) error
	Read(id uuid.UUID) (models.GitLabIntegration, error)
	FindByOrganizationId(orgID uuid.UUID) ([]models.GitLabIntegration, error)
	Delete(tx DB, id uuid.UUID) error
}

type GitLabOauth2TokenRepository interface {
	Save(tx DB, model ...*models.GitLabOauth2Token) error
	FindByUserIdAndProviderId(userId string, providerId string) (*models.GitLabOauth2Token, error)
	FindByUserId(userId string) ([]models.GitLabOauth2Token, error)
	Delete(tx DB, tokens []models.GitLabOauth2Token) error
	DeleteByUserIdAndProviderId(userId string, providerId string) error
	CreateIfNotExists(tokens []*models.GitLabOauth2Token) error
}

type ConfigService interface {
	GetJSONConfig(key string, v any) error
	SetJSONConfig(key string, v any) error
}

type StatisticsRepository interface {
	TimeTravelDependencyVulnState(assetVersionName string, assetID uuid.UUID, time time.Time) ([]models.DependencyVuln, error)
	GetAssetRiskDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error)
	GetAssetCvssDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error)
	GetDependencyVulnCountByScannerId(assetVersionName string, assetID uuid.UUID) (map[string]int, error)
	AverageFixingTime(assetVersionName string, assetID uuid.UUID, riskIntervalStart, riskIntervalEnd float64) (time.Duration, error)
	CVESWithKnownExploitsInAssetVersion(assetVersion models.AssetVersion) ([]models.CVE, error)
}

type AssetRiskHistoryRepository interface {
	GetRiskHistory(assetVersionName string, assetID uuid.UUID, start, end time.Time) ([]models.AssetRiskHistory, error)
	GetRiskHistoryByProject(projectId uuid.UUID, day time.Time) ([]models.AssetRiskHistory, error)
	UpdateRiskAggregation(assetRisk *models.AssetRiskHistory) error
}

type ProjectRiskHistoryRepository interface {
	GetRiskHistory(projectId uuid.UUID, start, end time.Time) ([]models.ProjectRiskHistory, error)
	UpdateRiskAggregation(projectRisk *models.ProjectRiskHistory) error
}

type StatisticsService interface {
	UpdateAssetRiskAggregation(assetVersion *models.AssetVersion, assetID uuid.UUID, begin time.Time, end time.Time, propagateToProject bool) error
	GetAssetVersionCvssDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error)
}

type DepsDevService interface {
	GetProject(ctx context.Context, projectID string) (common.DepsDevProjectResponse, error)
	GetVersion(ctx context.Context, ecosystem, packageName, version string) (common.DepsDevVersionResponse, error)
}

type ComponentProjectRepository interface {
	common.Repository[string, models.ComponentProject, DB]
}

type ComponentService interface {
	GetAndSaveLicenseInformation(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.Component, error)
	RefreshComponentProjectInformation(project models.ComponentProject)
	GetLicense(component models.Component) (models.Component, error)
}

type AccessControl interface {
	HasAccess(subject string) (bool, error) // return error if couldnt be checked due to unauthorized access or other issues

	InheritRole(roleWhichGetsPermissions, roleWhichProvidesPermissions string) error

	GetAllRoles(user string) []string

	GrantRole(subject string, role string) error
	RevokeRole(subject string, role string) error

	GrantRoleInProject(subject string, role string, project string) error
	RevokeRoleInProject(subject string, role string, project string) error
	InheritProjectRole(roleWhichGetsPermissions, roleWhichProvidesPermissions string, project string) error

	InheritProjectRolesAcrossProjects(roleWhichGetsPermissions, roleWhichProvidesPermissions ProjectRole) error

	LinkDomainAndProjectRole(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions string, project string) error

	AllowRole(role string, object Object, action []Action) error
	IsAllowed(subject string, object Object, action Action) (bool, error)

	IsAllowedInProject(project *models.Project, user string, object Object, action Action) (bool, error)
	AllowRoleInProject(project string, role string, object Object, action []Action) error

	GetAllProjectsForUser(user string) (any, error) // return is either a slice of strings or projects

	GetOwnerOfOrganization() (string, error)

	GetAllMembersOfOrganization() ([]string, error)

	GetAllMembersOfProject(projectID string) ([]string, error)

	GetDomainRole(user string) (string, error)
	GetProjectRole(user string, project string) (string, error)

	GetExternalEntityProviderID() *string
}

type RBACProvider interface {
	GetDomainRBAC(domain string) AccessControl
	DomainsOfUser(user string) ([]string, error)
}

type RBACMiddleware = func(obj Object, act Action) echo.MiddlewareFunc

const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

type Action string

const (
	ActionCreate Action = "create"
	ActionRead   Action = "read"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

type Object string

const (
	ObjectProject      Object = "project"
	ObjectAsset        Object = "asset"
	ObjectUser         Object = "user"
	ObjectOrganization Object = "organization"
)

type ProjectRole struct {
	Project string
	Role    string
}
