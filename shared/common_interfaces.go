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

package shared

import (
	"context"
	"net/http"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/google/uuid"
	toto "github.com/in-toto/in-toto-golang/in_toto"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm/clause"
)

type DaemonRunner interface {
	RunDaemonPipelineForAsset(ctx context.Context, assetID uuid.UUID) error
	RunAssetPipeline(ctx context.Context, forceAll bool)
	UpdateFixedVersions(ctx context.Context) error
	UpdateVulnDB(ctx context.Context) error
	UpdateOpenSourceInsightInformation(ctx context.Context) error

	Start(ctx context.Context)
}

type FixedVersionResolver interface {
	ResolveFixedVersions(path []packageurl.PackageURL, fixedVersion string) (string, error)
}

type LeaderElector interface {
	IsLeader() bool
}
type ReleaseService interface {
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]models.Release, error)
	ListByProjectPaged(ctx context.Context, projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.Release], error)
	Read(ctx context.Context, id uuid.UUID) (models.Release, error)
	ReadRecursive(ctx context.Context, id uuid.UUID) (models.Release, error)
	Create(ctx context.Context, r *models.Release) error
	Update(ctx context.Context, r *models.Release) error
	Delete(ctx context.Context, id uuid.UUID) error
	AddItem(ctx context.Context, item *models.ReleaseItem) error
	RemoveItem(ctx context.Context, id uuid.UUID) error
	ListCandidates(ctx context.Context, projectID uuid.UUID, releaseID *uuid.UUID) ([]models.Artifact, []models.Release, error)
}

type PersonalAccessTokenService interface {
	VerifyRequestSignature(ctx context.Context, req *http.Request) (string, string, error)
	RevokeByPrivateKey(ctx context.Context, privKey string) error
	ToModel(ctx context.Context, request dtos.PatCreateRequest, userID string) models.PAT
}

type CSAFService interface {
	GetVexFromCsafProvider(ctx context.Context, purl packageurl.PackageURL, domain string) (*cyclonedx.BOM, error)
	GenerateCSAFReport(ctx context.Context, orgName string, assetID uuid.UUID, assetName string, cveID string) (csaf.Advisory, error)
	GetOldestVulnPerUniqueCVE(ctx context.Context, assetID uuid.UUID) ([]models.DependencyVuln, error)
}

type SBOMScanner interface {
	Scan(ctx context.Context, bom *normalize.SBOMGraph) ([]models.VulnInPackage, error)
}
type ProjectRepository interface {
	Read(ctx context.Context, tx DB, projectID uuid.UUID) (models.Project, error)
	ReadBySlug(ctx context.Context, tx DB, organizationID uuid.UUID, slug string) (models.Project, error)
	ReadBySlugUnscoped(ctx context.Context, tx DB, organizationID uuid.UUID, slug string) (models.Project, error)
	Update(ctx context.Context, tx DB, project *models.Project) error
	Delete(ctx context.Context, tx DB, projectID uuid.UUID) error
	Create(ctx context.Context, tx DB, project *models.Project) error
	Activate(ctx context.Context, tx DB, projectID uuid.UUID) error
	RecursivelyGetChildProjects(ctx context.Context, tx DB, projectID uuid.UUID) ([]models.Project, error)
	GetDirectChildProjects(ctx context.Context, tx DB, projectID uuid.UUID) ([]models.Project, error)
	GetByOrgID(ctx context.Context, tx DB, organizationID uuid.UUID) ([]models.Project, error)
	GetProjectByAssetID(ctx context.Context, tx DB, assetID uuid.UUID) (models.Project, error)
	List(ctx context.Context, tx DB, idSlice []uuid.UUID, parentID *uuid.UUID, organizationID uuid.UUID) ([]models.Project, error)
	ListPaged(ctx context.Context, tx DB, projectIDs []uuid.UUID, parentID *uuid.UUID, orgID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.Project], error)
	EnablePolicyForProject(ctx context.Context, tx DB, projectID uuid.UUID, policyID uuid.UUID) error
	DisablePolicyForProject(ctx context.Context, tx DB, projectID uuid.UUID, policyID uuid.UUID) error
	Upsert(ctx context.Context, tx DB, projects *[]*models.Project, conflictingColumns []clause.Column, toUpdate []string) error
	EnableCommunityManagedPolicies(ctx context.Context, tx DB, projectID uuid.UUID) error
	UpsertSplit(ctx context.Context, tx DB, externalProviderID string, projects []*models.Project) ([]*models.Project, []*models.Project, error)
	ListSubProjectsAndAssets(ctx context.Context, tx DB, allowedAssetIDs []string, allowedProjectIDs []uuid.UUID, parentID *uuid.UUID, orgID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[dtos.ProjectAssetDTO], error)
}

type Verifier interface {
	VerifyRequestSignature(ctx context.Context, req *http.Request) (string, string, error)
}

type PolicyRepository interface {
	utils.Repository[uuid.UUID, models.Policy, DB]
	FindByProjectID(ctx context.Context, tx DB, projectID uuid.UUID) ([]models.Policy, error)
	FindByOrganizationID(ctx context.Context, tx DB, organizationID uuid.UUID) ([]models.Policy, error)
	FindCommunityManagedPolicies(ctx context.Context, tx DB) ([]models.Policy, error)
}

type AssetRepository interface {
	utils.Repository[uuid.UUID, models.Asset, DB]
	GetAllowedAssetsByProjectID(ctx context.Context, tx DB, allowedAssetIDs []string, projectID uuid.UUID) ([]models.Asset, error)
	GetByProjectID(ctx context.Context, tx DB, projectID uuid.UUID) ([]models.Asset, error)
	GetByOrgID(ctx context.Context, tx DB, organizationID uuid.UUID) ([]models.Asset, error)
	FindByName(ctx context.Context, tx DB, name string) (models.Asset, error)
	FindAssetByExternalProviderID(ctx context.Context, tx DB, externalEntityProviderID string, externalEntityID string) (*models.Asset, error)
	GetFQNByID(ctx context.Context, tx DB, id uuid.UUID) (string, error)
	ReadBySlug(ctx context.Context, tx DB, projectID uuid.UUID, slug string) (models.Asset, error)
	GetAssetIDBySlug(ctx context.Context, tx DB, projectID uuid.UUID, slug string) (uuid.UUID, error)
	Update(ctx context.Context, tx DB, asset *models.Asset) error
	ReadBySlugUnscoped(ctx context.Context, tx DB, projectID uuid.UUID, slug string) (models.Asset, error)
	GetAllAssetsFromDB(ctx context.Context, tx DB) ([]models.Asset, error)
	ReadWithAssetVersions(ctx context.Context, tx DB, assetID uuid.UUID) (models.Asset, error)
	GetAssetsWithVulnSharingEnabled(ctx context.Context, tx DB, orgID uuid.UUID) ([]models.Asset, error)
}

type AttestationRepository interface {
	utils.Repository[string, models.Attestation, DB]
	GetByAssetID(ctx context.Context, tx DB, assetID uuid.UUID) ([]models.Attestation, error)
	GetByAssetVersionAndAssetID(ctx context.Context, tx DB, assetID uuid.UUID, assetVersion string) ([]models.Attestation, error)
}

type ArtifactRepository interface {
	utils.Repository[string, models.Artifact, DB]
	GetByAssetIDAndAssetVersionName(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string) ([]models.Artifact, error)
	ReadArtifact(ctx context.Context, tx DB, name string, assetVersionName string, assetID uuid.UUID) (models.Artifact, error)
	DeleteArtifact(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string, artifactName string) error
	GetAllArtifactAffectedByDependencyVuln(ctx context.Context, tx DB, vulnID string) ([]models.Artifact, error)
	GetByAssetVersions(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionNames []string) ([]models.Artifact, error)
	CleanupOrphanedRecords(ctx context.Context) error
}

type ReleaseRepository interface {
	utils.Repository[uuid.UUID, models.Release, DB]
	GetByProjectID(ctx context.Context, tx DB, projectID uuid.UUID) ([]models.Release, error)
	ReadWithItems(ctx context.Context, tx DB, id uuid.UUID) (models.Release, error)
	ReadRecursive(ctx context.Context, tx DB, id uuid.UUID) (models.Release, error)
	GetByProjectIDPaged(ctx context.Context, tx DB, projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.Release], error)
	CreateReleaseItem(ctx context.Context, tx DB, item *models.ReleaseItem) error
	DeleteReleaseItem(ctx context.Context, tx DB, id uuid.UUID) error
	GetCandidateItemsForRelease(ctx context.Context, tx DB, projectID uuid.UUID, releaseID *uuid.UUID) ([]models.Artifact, []models.Release, error)
}

type CveRepository interface {
	utils.Repository[string, models.CVE, DB]
	FindByID(ctx context.Context, tx DB, id string) (models.CVE, error)
	GetLastModDate(ctx context.Context, tx DB) (time.Time, error)
	GetAllCVEsID(ctx context.Context, tx DB) ([]string, error)
	SaveCveAffectedComponents(ctx context.Context, tx DB, cveID string, affectedComponentHashes []string) error
	FindCVE(ctx context.Context, tx DB, id string) (models.CVE, error)
	FindCVEs(ctx context.Context, tx DB, ids []string) ([]models.CVE, error)
	FindAllListPaged(ctx context.Context, tx DB, pageInfo PageInfo, filter []FilterQuery, sort []SortQuery) (Paged[models.CVE], error)
	CreateCVEWithConflictHandling(ctx context.Context, tx DB, cve *models.CVE) error
	CreateCVEAffectedComponentsEntries(ctx context.Context, tx DB, cve *models.CVE, components []models.AffectedComponent) error
	UpdateEpssBatch(ctx context.Context, tx DB, batch []models.CVE) error
	UpdateCISAKEVBatch(ctx context.Context, tx DB, batch []models.CVE) error
}

type CweRepository interface {
	GetAllCWEsID(ctx context.Context, tx DB) ([]string, error)
	SaveBatch(ctx context.Context, tx DB, cwes []models.CWE) error
}

type ExploitRepository interface {
	GetAllExploitsID(ctx context.Context, tx DB) ([]string, error)
	SaveBatch(ctx context.Context, tx DB, exploits []models.Exploit) error
}

type AffectedComponentRepository interface {
	utils.Repository[string, models.AffectedComponent, DB]
	GetAllAffectedComponentsID(ctx context.Context, tx DB) ([]string, error)
	DeleteAll(ctx context.Context, tx DB, ecosystem string) error
	CreateAffectedComponentsUsingUnnest(ctx context.Context, tx DB, components []models.AffectedComponent) error
}

type MaliciousPackageChecker interface {
	DownloadAndProcessDB(ctx context.Context) error
	IsMalicious(ctx context.Context, ecosystem, packageName, version string) (bool, *dtos.OSV)
}

type ComponentRepository interface {
	utils.Repository[string, models.Component, DB]
	LoadComponents(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID) ([]models.ComponentDependency, error)
	LoadComponentsWithProject(ctx context.Context, tx DB, overwrittenLicenses []models.LicenseRisk, assetVersionName string, assetID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.ComponentDependency], error)
	SearchComponentOccurrencesByProject(ctx context.Context, tx DB, projectIDs []uuid.UUID, pageInfo PageInfo, search string) (Paged[models.ComponentOccurrence], error)
	FindByPurl(ctx context.Context, tx DB, purl string) (models.Component, error)
	HandleStateDiff(ctx context.Context, tx DB, assetVersion models.AssetVersion, wholeAssetGraph *normalize.SBOMGraph, diff normalize.GraphDiff) error
	CreateComponents(ctx context.Context, tx DB, components []models.ComponentDependency) error
	FetchInformationSources(ctx context.Context, tx DB, artifact *models.Artifact) ([]models.ComponentDependency, error)
	RemoveInformationSources(ctx context.Context, tx DB, artifact *models.Artifact, rootNodePurls []string) error
}

type DependencyVulnRepository interface {
	utils.Repository[string, models.DependencyVuln, DB]
	GetByAssetID(ctx context.Context, tx DB, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetAllVulnsByAssetID(ctx context.Context, tx DB, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetAllVulnsByAssetIDWithTicketIDs(ctx context.Context, tx DB, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetDependencyVulnByCVEIDAndAssetID(ctx context.Context, tx DB, cveID string, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetAllOpenVulnsByAssetVersionNameAndAssetID(ctx context.Context, tx DB, artifactName *string, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetDependencyVulnsByAssetVersion(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error)
	GetByAssetVersionPaged(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], map[string]int, error)
	GetDefaultDependencyVulnsByOrgIDPaged(ctx context.Context, tx DB, userAllowedProjectIds []string, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)
	GetDefaultDependencyVulnsByProjectIDPaged(ctx context.Context, tx DB, projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)
	GetDependencyVulnsByAssetVersionPagedAndFlat(ctx context.Context, tx DB, assetVersionName string, assetVersionID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)
	ListByAssetAndAssetVersion(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetDependencyVulnsByPurl(ctx context.Context, tx DB, purls []string) ([]models.DependencyVuln, error)
	ApplyAndSave(ctx context.Context, tx DB, dependencyVuln *models.DependencyVuln, vulnEvent *models.VulnEvent) error
	GetDependencyVulnsByDefaultAssetVersion(ctx context.Context, tx DB, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error)
	ListUnfixedByAssetAndAssetVersion(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error)
	GetHintsInOrganizationForVuln(ctx context.Context, tx DB, orgID uuid.UUID, pURL string, cveID string) (dtos.DependencyVulnHints, error)
	GetAllByAssetIDAndState(ctx context.Context, tx DB, assetID uuid.UUID, state dtos.VulnState, durationSinceStateChange time.Duration) ([]models.DependencyVuln, error)
	GetDependencyVulnsByOtherAssetVersions(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetAllVulnsByArtifact(ctx context.Context, tx DB, artifact models.Artifact) ([]models.DependencyVuln, error)
	GetAllVulnsForTagsAndDefaultBranchInAsset(ctx context.Context, tx DB, assetID uuid.UUID, excludedStates []dtos.VulnState) ([]models.DependencyVuln, error)
	// regardless of path. Used for applying status changes to all instances of a CVE+component combination.
	FindByCVEAndComponentPurl(ctx context.Context, tx DB, assetID uuid.UUID, cveID string, componentPurl string) ([]models.DependencyVuln, error)
}

type FirstPartyVulnRepository interface {
	utils.Repository[string, models.FirstPartyVuln, DB]
	GetDefaultFirstPartyVulnsByProjectIDPaged(ctx context.Context, tx DB, projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVuln], error)
	GetDefaultFirstPartyVulnsByOrgIDPaged(ctx context.Context, tx DB, userAllowedProjectIds []string, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVuln], error)
	GetByAssetID(ctx context.Context, tx DB, assetID uuid.UUID) ([]models.FirstPartyVuln, error)
	GetByAssetVersionPaged(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVuln], map[string]int, error)
	ListByScanner(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVuln, error)
	ApplyAndSave(ctx context.Context, tx DB, dependencyVuln *models.FirstPartyVuln, vulnEvent *models.VulnEvent) error
	GetByAssetVersion(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID) ([]models.FirstPartyVuln, error)
	GetFirstPartyVulnsByOtherAssetVersions(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVuln, error)
	ListUnfixedByAssetAndAssetVersionAndScanner(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVuln, error)
}

type LicenseRiskRepository interface {
	utils.Repository[string, models.LicenseRisk, DB]
	GetByAssetID(ctx context.Context, tx DB, assetID uuid.UUID) ([]models.LicenseRisk, error)
	GetAllLicenseRisksForAssetVersionPaged(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.LicenseRisk], error)
	GetAllLicenseRisksForAssetVersion(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string) ([]models.LicenseRisk, error)
	GetLicenseRisksByOtherAssetVersions(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID) ([]models.LicenseRisk, error)
	GetAllOverwrittenLicensesForAssetVersion(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string) ([]models.LicenseRisk, error)
	MaybeGetLicenseOverwriteForComponent(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string, pURL packageurl.PackageURL) (models.LicenseRisk, error)
	DeleteByComponentPurl(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string, purl packageurl.PackageURL) error
	ListByArtifactName(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.LicenseRisk, error)
	ApplyAndSave(ctx context.Context, tx DB, licenseRisk *models.LicenseRisk, vulnEvent *models.VulnEvent) error
}

type InTotoLinkRepository interface {
	utils.Repository[uuid.UUID, models.InTotoLink, DB]
	FindByAssetAndSupplyChainID(ctx context.Context, tx DB, assetID uuid.UUID, supplyChainID string) ([]models.InTotoLink, error)
	FindBySupplyChainID(ctx context.Context, tx DB, supplyChainID string) ([]models.InTotoLink, error)
}

type PersonalAccessTokenRepository interface {
	utils.Repository[uuid.UUID, models.PAT, DB]
	GetByFingerprint(ctx context.Context, tx DB, fingerprint string) (models.PAT, error)
	FindByUserIDs(ctx context.Context, tx DB, userID []uuid.UUID) ([]models.PAT, error)
	ListByUserID(ctx context.Context, tx DB, userID string) ([]models.PAT, error)
	DeleteByFingerprint(ctx context.Context, tx DB, fingerprint string) error
	MarkAsLastUsedNow(ctx context.Context, tx DB, fingerprint string) error
}

type SupplyChainRepository interface {
	utils.Repository[uuid.UUID, models.SupplyChain, DB]
	FindByDigest(ctx context.Context, tx DB, digest string) ([]models.SupplyChain, error)
	FindBySupplyChainID(ctx context.Context, tx DB, supplyChainID string) ([]models.SupplyChain, error)
	PercentageOfVerifiedSupplyChains(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID) (float64, error)
}

type VEXRuleRepository interface {
	GetDB(ctx context.Context, db DB) DB
	FindByAssetVersion(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string) ([]models.VEXRule, error)
	FindByAssetVersionPaged(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string, pageInfo PageInfo, search string, filterQuery []FilterQuery, sortQuery []SortQuery) (Paged[models.VEXRule], error)
	FindByID(ctx context.Context, tx DB, id string) (models.VEXRule, error)
	FindByAssetAndVexSource(ctx context.Context, tx DB, assetID uuid.UUID, vexSource string) ([]models.VEXRule, error)
	Create(ctx context.Context, tx DB, rule *models.VEXRule) error
	Upsert(ctx context.Context, tx DB, rule *models.VEXRule) error
	UpsertBatch(ctx context.Context, tx DB, rules []models.VEXRule) error
	Update(ctx context.Context, tx DB, rule *models.VEXRule) error
	Delete(ctx context.Context, tx DB, rule models.VEXRule) error
	DeleteBatch(ctx context.Context, tx DB, rules []models.VEXRule) error
	DeleteByAssetVersion(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string) error
	Begin(ctx context.Context) DB
	FindByAssetVersionAndCVE(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string, cveID string) ([]models.VEXRule, error)
}

type OrganizationRepository interface {
	utils.Repository[uuid.UUID, models.Org, DB]
	ReadBySlug(ctx context.Context, tx DB, slug string) (models.Org, error)
	Update(ctx context.Context, tx DB, organization *models.Org) error
	ContentTree(ctx context.Context, tx DB, orgID uuid.UUID, projects []string) []any // returns project dtos as values - including fetched assets
	GetOrgByID(ctx context.Context, tx DB, id uuid.UUID) (models.Org, error)
	GetOrgsWithVulnSharingAssets(ctx context.Context, tx DB) ([]models.Org, error)
}

type OrgService interface {
	CreateOrganization(ctx Context, organization *models.Org) error
	ReadBySlug(ctx context.Context, slug string) (*models.Org, error)
}

type InvitationRepository interface {
	Save(ctx context.Context, tx DB, invitation *models.Invitation) error
	FindByCode(ctx context.Context, tx DB, code string) (models.Invitation, error)
	Delete(ctx context.Context, tx DB, id uuid.UUID) error
}

type ExternalReferenceRepository interface {
	utils.Repository[uuid.UUID, models.ExternalReference, DB]
	FindByAssetVersion(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string) ([]models.ExternalReference, error)
}

type ExternalEntityProviderService interface {
	RefreshExternalEntityProviderProjects(ctx Context, org models.Org, user string) error
	TriggerOrgSync(c Context) error
	SyncOrgs(c Context) ([]*models.Org, error)
	TriggerSync(c Context) error
}

type ProjectService interface {
	ReadBySlug(ctx Context, organizationID uuid.UUID, slug string) (models.Project, error)
	ListAllowedProjects(ctx Context) ([]models.Project, error)
	ListAllowedProjectsPaged(c Context) (Paged[models.Project], error)
	ListAllowedSubProjectsAndAssetsPaged(c Context) (Paged[dtos.ProjectAssetDTO], error)
	ListProjectsByOrganizationID(ctx context.Context, organizationID uuid.UUID) ([]models.Project, error)
	RecursivelyGetChildProjects(ctx context.Context, projectID uuid.UUID) ([]models.Project, error)
	GetDirectChildProjects(ctx context.Context, projectID uuid.UUID) ([]models.Project, error)
	CreateProject(ctx Context, project *models.Project) error
	BootstrapProject(ctx context.Context, rbac AccessControl, project *models.Project) error
}

type InTotoVerifierService interface {
	VerifySupplyChainWithOutputDigest(ctx context.Context, supplyChainID string, digest string) (bool, error)
	VerifySupplyChain(ctx context.Context, supplyChainID string) (bool, error)
	VerifySupplyChainByDigestOnly(ctx context.Context, digest string) (bool, error)
	HexPublicKeyToInTotoKey(hexPubKey string) (toto.Key, error)
}

type AssetService interface {
	UpdateAssetRequirements(ctx context.Context, asset models.Asset, responsible string, justification string) error
	GetCVSSBadgeSVG(ctx context.Context, results []models.ArtifactRiskHistory) string
	CreateAsset(ctx context.Context, rbac AccessControl, currentUserID string, asset models.Asset) (*models.Asset, error)
	BootstrapAsset(ctx context.Context, rbac AccessControl, asset *models.Asset) error
}
type ArtifactService interface {
	GetArtifactsByAssetIDAndAssetVersionName(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string) ([]models.Artifact, error)
	SaveArtifact(ctx context.Context, artifact *models.Artifact) error
	DeleteArtifact(ctx context.Context, assetID uuid.UUID, assetVersionName string, artifactName string) error
	ReadArtifact(ctx context.Context, tx DB, name string, assetVersionName string, assetID uuid.UUID) (models.Artifact, error)
}

type DependencyVulnService interface {
	RecalculateRawRiskAssessment(ctx context.Context, tx DB, userID string, dependencyVulns []models.DependencyVuln, justification string, asset models.Asset) ([]models.DependencyVuln, error)
	UserFixedDependencyVulns(ctx context.Context, tx DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset) error
	UserDetectedDependencyVulns(ctx context.Context, tx DB, artifactName string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset) error
	UserDetectedExistingVulnOnDifferentBranch(ctx context.Context, tx DB, artifactName string, dependencyVulns []statemachine.BranchVulnMatch[*models.DependencyVuln], assetVersion models.AssetVersion, asset models.Asset) error
	UserDetectedDependencyVulnInAnotherArtifact(ctx context.Context, tx DB, vulnerabilities []models.DependencyVuln, artifactName string) error
	UserDidNotDetectDependencyVulnInArtifactAnymore(ctx context.Context, tx DB, vulnerabilities []models.DependencyVuln, artifactName string) error
	CreateVulnEventAndApply(ctx context.Context, tx DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, status dtos.VulnEventType, justification string, mechanicalJustification dtos.MechanicalJustificationType, assetVersionName string) (models.VulnEvent, error)
	SyncIssues(ctx context.Context, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, vulnList []models.DependencyVuln) error
	SyncAllIssues(ctx context.Context, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion) error
	GetAllUniqueCVEsForAsset(ctx context.Context, assetID uuid.UUID, compareFunc func(existingLeader models.DependencyVuln, newVuln models.DependencyVuln) bool) ([]models.DependencyVuln, error)
}

type AssetVersionService interface {
	BuildVeX(ctx context.Context, tx DB, frontendURL string, orgName string, orgSlug string, projectSlug string, asset models.Asset, assetVersion models.AssetVersion, dependencyVulns []models.DependencyVuln) *normalize.SBOMGraph
	GetAssetVersionsByAssetID(ctx context.Context, tx DB, assetID uuid.UUID) ([]models.AssetVersion, error)
	UpdateSBOM(ctx context.Context, tx DB, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifactName string, sbom *normalize.SBOMGraph) (*normalize.SBOMGraph, error)
	BuildOpenVeX(ctx context.Context, tx DB, asset models.Asset, assetVersion models.AssetVersion, organizationSlug string, dependencyVulns []models.DependencyVuln) vex.VEX
	LoadFullSBOMGraph(ctx context.Context, tx DB, assetVersion models.AssetVersion) (*normalize.SBOMGraph, error)
}

type AssetVersionRepository interface {
	All(ctx context.Context, tx DB) ([]models.AssetVersion, error)
	Read(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID) (models.AssetVersion, error)
	GetDB(ctx context.Context, tx DB) DB
	Begin(ctx context.Context) DB
	Delete(ctx context.Context, tx DB, assetVersion *models.AssetVersion) error
	Save(ctx context.Context, tx DB, assetVersion *models.AssetVersion) error
	GetAssetVersionsByAssetID(ctx context.Context, tx DB, assetID uuid.UUID) ([]models.AssetVersion, error)
	GetAssetVersionsByAssetIDWithArtifacts(ctx context.Context, tx DB, assetID uuid.UUID) ([]models.AssetVersion, error)
	GetDefaultAssetVersionsByProjectID(ctx context.Context, tx DB, projectID uuid.UUID) ([]models.AssetVersion, error)
	GetDefaultAssetVersionsByProjectIDs(ctx context.Context, tx DB, projectIDs []uuid.UUID) ([]models.AssetVersion, error)
	FindOrCreate(ctx context.Context, tx DB, assetVersionName string, assetID uuid.UUID, tag bool, defaultBranchName *string) (models.AssetVersion, error)
	ReadBySlug(ctx context.Context, tx DB, assetID uuid.UUID, slug string) (models.AssetVersion, error)
	GetDefaultAssetVersion(ctx context.Context, tx DB, assetID uuid.UUID) (models.AssetVersion, error)
	GetAllTagsAndDefaultBranchForAsset(ctx context.Context, tx DB, assetID uuid.UUID) ([]models.AssetVersion, error)
	UpdateAssetDefaultBranch(ctx context.Context, tx DB, assetID uuid.UUID, defaultBranch string) error
	DeleteOldAssetVersions(ctx context.Context, tx DB, day int) (int64, error)
	DeleteOldAssetVersionsOfAsset(ctx context.Context, tx DB, assetID uuid.UUID, day int) (int64, error)
	GetAmountOfAssetVersionsInOrg(ctx context.Context, tx DB, orgID uuid.UUID) (int, error)
}

type FirstPartyVulnService interface {
	UserFixedFirstPartyVulns(ctx context.Context, tx DB, userID string, firstPartyVulns []models.FirstPartyVuln) error
	UserDetectedFirstPartyVulns(ctx context.Context, tx DB, userID string, scannerID string, firstPartyVulns []models.FirstPartyVuln) error
	UserDetectedExistingFirstPartyVulnOnDifferentBranch(ctx context.Context, tx DB, scannerID string, firstPartyVulns []statemachine.BranchVulnMatch[*models.FirstPartyVuln], assetVersion models.AssetVersion, asset models.Asset) error
	UpdateFirstPartyVulnState(ctx context.Context, tx DB, userID string, firstPartyVuln *models.FirstPartyVuln, statusType string, justification string, mechanicalJustification dtos.MechanicalJustificationType) (models.VulnEvent, error)
	SyncIssues(ctx context.Context, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, vulnList []models.FirstPartyVuln) error
	SyncAllIssues(ctx context.Context, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion) error
}

type ScanService interface {
	ScanNormalizedSBOM(ctx context.Context, tx DB, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, normalizedBom *normalize.SBOMGraph, userID string) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, error)
	HandleScanResult(ctx context.Context, tx DB, org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sbom *normalize.SBOMGraph, vulns []models.VulnInPackage, artifactName string, userID string) (opened []models.DependencyVuln, closed []models.DependencyVuln, newState []models.DependencyVuln, err error)
	HandleFirstPartyVulnResult(ctx context.Context, org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sarifScan sarif.SarifSchema210Json, scannerID string, userID string) ([]models.FirstPartyVuln, []models.FirstPartyVuln, []models.FirstPartyVuln, error)
	FetchSbomsFromUpstream(ctx context.Context, artifactName string, ref string, upstreamURLs []string, keepOriginalSbomRootComponent bool) ([]*normalize.SBOMGraph, []string, []dtos.ExternalReferenceError)
	FetchVexFromUpstream(ctx context.Context, upstreamURLs []models.ExternalReference) ([]*normalize.VexReport, []models.ExternalReference, []models.ExternalReference)
	RunArtifactSecurityLifecycle(ctx context.Context, tx DB, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, userID string) (*normalize.SBOMGraph, []*normalize.VexReport, []models.DependencyVuln, error)
	ScanSBOMWithoutSaving(ctx context.Context, bom *cyclonedx.BOM) (dtos.ScanResponse, error)
}

type ConfigRepository interface {
	Save(ctx context.Context, tx DB, config *models.Config) error
	GetDB(ctx context.Context, tx DB) DB
}

type VEXRuleService interface {
	Begin(ctx context.Context) DB
	Create(ctx context.Context, tx DB, rule *models.VEXRule) error
	Update(ctx context.Context, tx DB, rule *models.VEXRule) error
	Delete(ctx context.Context, tx DB, rule models.VEXRule) error
	DeleteByAssetVersion(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string) error
	FindByAssetVersion(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string) ([]models.VEXRule, error)
	FindByAssetVersionPaged(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string, pageInfo PageInfo, search string, filterQuery []FilterQuery, sortQuery []SortQuery) (Paged[models.VEXRule], error)
	ApplyRulesToExistingVulns(ctx context.Context, tx DB, rules []models.VEXRule) ([]models.DependencyVuln, error)
	ApplyRulesToExistingVulnsForce(ctx context.Context, tx DB, rules []models.VEXRule) ([]models.DependencyVuln, error)
	ApplyRulesToExisting(ctx context.Context, tx DB, rules []models.VEXRule, vulns []models.DependencyVuln) ([]models.DependencyVuln, error)
	ApplyRulesToExistingForce(ctx context.Context, tx DB, rules []models.VEXRule, vulns []models.DependencyVuln) ([]models.DependencyVuln, error)
	IngestVEX(ctx context.Context, tx DB, asset models.Asset, assetVersion models.AssetVersion, vexReport *normalize.VexReport) error
	IngestVexes(ctx context.Context, tx DB, asset models.Asset, assetVersion models.AssetVersion, vexReports []*normalize.VexReport) error
	CountMatchingVulns(ctx context.Context, tx DB, rule models.VEXRule) (int, error)
	CountMatchingVulnsForRules(ctx context.Context, tx DB, rules []models.VEXRule) (map[string]int, error)
	FindByID(ctx context.Context, tx DB, id string) (models.VEXRule, error)
	FindByAssetVersionAndCVE(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string, cveID string) ([]models.VEXRule, error)
	FindByAssetVersionAndVulnID(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string, vulnID string) ([]models.VEXRule, error)
}

type VulnEventRepository interface {
	SaveBatch(ctx context.Context, tx DB, events []models.VulnEvent) error
	SaveBatchBestEffort(ctx context.Context, tx DB, events []models.VulnEvent) error
	Save(ctx context.Context, tx DB, event *models.VulnEvent) error
	ReadAssetEventsByVulnID(ctx context.Context, tx DB, vulnID string, vulnType dtos.VulnType) ([]models.VulnEventDetail, error)
	ReadEventsByAssetIDAndAssetVersionName(ctx context.Context, tx DB, assetID uuid.UUID, assetVersionName string, pageInfo PageInfo, filter []FilterQuery) (Paged[models.VulnEventDetail], error)
	GetSecurityRelevantEventsForVulnIDs(ctx context.Context, tx DB, vulnIDs []string) ([]models.VulnEvent, error)
	GetLastEventBeforeTimestamp(ctx context.Context, tx DB, vulnID string, time time.Time) (models.VulnEvent, error)
	DeleteEventByID(ctx context.Context, tx DB, eventID string) error
	HasAccessToEvent(ctx context.Context, tx DB, assetID uuid.UUID, eventID string) (bool, error)
}

type GithubAppInstallationRepository interface {
	Save(ctx context.Context, tx DB, model *models.GithubAppInstallation) error
	Read(ctx context.Context, tx DB, installationID int) (models.GithubAppInstallation, error)
	FindByOrganizationID(ctx context.Context, tx DB, orgID uuid.UUID) ([]models.GithubAppInstallation, error)
	Delete(ctx context.Context, tx DB, installationID int) error
}

type VulnRepository interface {
	FindByTicketID(ctx context.Context, tx DB, ticketID string) (models.Vuln, error)
	Save(ctx context.Context, tx DB, vuln *models.Vuln) error
	Transaction(ctx context.Context, fn func(tx DB) error) error
	GetOrgFromVuln(ctx context.Context, tx DB, vuln models.Vuln) (models.Org, error)
	ApplyAndSave(ctx context.Context, tx DB, dependencyVuln models.Vuln, vulnEvent *models.VulnEvent) error
}

type ExternalUserRepository interface {
	Save(ctx context.Context, tx DB, user *models.ExternalUser) error
	GetDB(ctx context.Context, tx DB) DB
	FindByOrgID(ctx context.Context, tx DB, orgID uuid.UUID) ([]models.ExternalUser, error)
}

type JiraIntegrationRepository interface {
	Save(ctx context.Context, tx DB, model *models.JiraIntegration) error
	Read(ctx context.Context, tx DB, id uuid.UUID) (models.JiraIntegration, error)
	FindByOrganizationID(ctx context.Context, tx DB, orgID uuid.UUID) ([]models.JiraIntegration, error)
	Delete(ctx context.Context, tx DB, id uuid.UUID) error
	GetClientByIntegrationID(ctx context.Context, tx DB, integrationID uuid.UUID) (models.JiraIntegration, error)
}

type WebhookIntegrationRepository interface {
	Save(ctx context.Context, tx DB, model *models.WebhookIntegration) error
	Read(ctx context.Context, tx DB, id uuid.UUID) (models.WebhookIntegration, error)
	FindByOrgIDAndProjectID(ctx context.Context, tx DB, orgID uuid.UUID, projectID uuid.UUID) ([]models.WebhookIntegration, error)
	Delete(ctx context.Context, tx DB, id uuid.UUID) error
	GetClientByIntegrationID(ctx context.Context, tx DB, integrationID uuid.UUID) (models.WebhookIntegration, error)
	GetProjectWebhooks(ctx context.Context, tx DB, orgID uuid.UUID, projectID uuid.UUID) ([]models.WebhookIntegration, error)
}

type GitlabIntegrationRepository interface {
	Save(ctx context.Context, tx DB, model *models.GitLabIntegration) error
	Read(ctx context.Context, tx DB, id uuid.UUID) (models.GitLabIntegration, error)
	FindByOrganizationID(ctx context.Context, tx DB, orgID uuid.UUID) ([]models.GitLabIntegration, error)
	Delete(ctx context.Context, tx DB, id uuid.UUID) error
}

type GitLabOauth2TokenRepository interface {
	Save(ctx context.Context, tx DB, model ...*models.GitLabOauth2Token) error
	FindByUserIDAndProviderID(ctx context.Context, tx DB, userID string, providerID string) (*models.GitLabOauth2Token, error)
	FindByUserID(ctx context.Context, tx DB, userID string) ([]models.GitLabOauth2Token, error)
	Delete(ctx context.Context, tx DB, tokens []models.GitLabOauth2Token) error
	DeleteByUserIDAndProviderID(ctx context.Context, tx DB, userID string, providerID string) error
	CreateIfNotExists(ctx context.Context, tx DB, tokens []*models.GitLabOauth2Token) error
}

type ConfigService interface {
	// retrieves the value for the given key and marshals it into v
	GetJSONConfig(ctx context.Context, key string, v any) error
	SetJSONConfig(ctx context.Context, key string, v any) error
}

type StatisticsRepository interface {
	TimeTravelDependencyVulnState(ctx context.Context, tx DB, artifactName *string, assetVersionName *string, assetID uuid.UUID, time time.Time) ([]models.DependencyVuln, error)
	AverageFixingTimes(ctx context.Context, artifactNam *string, assetVersionName string, assetID uuid.UUID) (dtos.RemediationTimeAverages, error)
	// AverageRemediationTimesForRelease computes all risk/CVSS average fixing times for a release tree in one query
	AverageRemediationTimesForRelease(ctx context.Context, tx DB, releaseID uuid.UUID) (dtos.RemediationTimeAverages, error)

	// CVSS-based average fixing time methods
	VulnClassificationByOrg(ctx context.Context, tx DB, orgID uuid.UUID) (dtos.Distribution, error)
	GetOrgStructureDistribution(ctx context.Context, tx DB, orgID uuid.UUID) (dtos.OrgStructureDistribution, error)
	GetMostVulnerableArtifactsInOrg(ctx context.Context, tx DB, orgID uuid.UUID, limit int) ([]dtos.VulnDistributionInStructure, error)
	GetMostVulnerableProjectsInOrg(ctx context.Context, tx DB, orgID uuid.UUID, limit int) ([]dtos.VulnDistributionInStructure, error)
	GetMostVulnerableAssetsInOrg(ctx context.Context, tx DB, orgID uuid.UUID, limit int) ([]dtos.VulnDistributionInStructure, error)
	GetMostUsedComponentsInOrg(ctx context.Context, tx DB, orgID uuid.UUID, limit int) ([]dtos.ComponentUsageAcrossOrg, error)
	GetMostCommonCVEsInOrg(ctx context.Context, tx DB, orgID uuid.UUID, limit int) ([]dtos.CVEOccurrencesAcrossOrg, error)
	GetWeeklyAveragePerVulnEventType(ctx context.Context, tx DB, orgID uuid.UUID) ([]dtos.VulnEventAverage, error)

	GetAverageAmountOfOpenCodeRisksForProjectsInOrg(ctx context.Context, tx DB, orgID uuid.UUID) (float32, error)
	GetAverageAmountOfOpenVulnsPerProjectBySeverityInOrg(ctx context.Context, tx DB, orgID uuid.UUID) (dtos.ProjectVulnCountAverageBySeverity, error)
	GetComponentDistributionInOrg(ctx context.Context, tx DB, orgID uuid.UUID) ([]dtos.ComponentOccurrenceCount, error)
	FindMaliciousPackagesInOrg(ctx context.Context, tx DB, orgID uuid.UUID) ([]dtos.MaliciousPackageInOrg, error)
	GetAverageAgeOfDependenciesAcrossOrg(ctx context.Context, tx DB, orgID uuid.UUID) (time.Duration, error)
	GetAverageRemediationTimesAcrossOrg(ctx context.Context, tx DB, orgID uuid.UUID) (dtos.AverageRemediationTimes, error)
	GetRemediationTypeDistributionAcrossOrg(ctx context.Context, tx DB, orgID uuid.UUID) ([]dtos.RemediationTypeDistributionRow, error)
	CVESWithKnownExploitsInAssetVersion(ctx context.Context, tx DB, assetVersion models.AssetVersion) ([]models.CVE, error)
}

type ArtifactRiskHistoryRepository interface {
	// artifactName if non-nil restricts the history to a single artifact (artifactName + assetVersionName + assetID)
	GetRiskHistory(ctx context.Context, tx DB, artifactName *string, assetVersionName string, assetID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error)
	// GetRiskHistoryByRelease collects artifact risk histories for all artifacts included in a release tree
	GetRiskHistoryForOrg(ctx context.Context, tx DB, orgID uuid.UUID, start, end time.Time) ([]dtos.OrgRiskHistory, error)
	GetRiskHistoryByRelease(ctx context.Context, tx DB, releaseID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error)
	UpdateRiskAggregation(ctx context.Context, tx DB, assetRisk *models.ArtifactRiskHistory) error
}

type ProjectRiskHistoryRepository interface {
	GetRiskHistory(ctx context.Context, tx DB, projectID uuid.UUID, start, end time.Time) ([]models.ProjectRiskHistory, error)
	UpdateRiskAggregation(ctx context.Context, tx DB, projectRisk *models.ProjectRiskHistory) error
}

type StatisticsService interface {
	UpdateArtifactRiskAggregation(ctx context.Context, artifact *models.Artifact, assetID uuid.UUID, begin time.Time, end time.Time) error
	GetArtifactRiskHistory(ctx context.Context, artifactName *string, assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistory, error)
	// Release scoped statistics
	GetReleaseRiskHistory(ctx context.Context, releaseID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistory, error)
	GetRemediationTimeAveragesForRelease(ctx context.Context, releaseID uuid.UUID) (dtos.RemediationTimeAverages, error)
	// CVSS-based average fixing time methods
	GetTopEcosystemsInOrg(ctx context.Context, orgID uuid.UUID, limit int) ([]dtos.EcosystemUsage, error)
	GetComponentRisk(ctx context.Context, artifactName *string, assetVersionName string, assetID uuid.UUID) (map[string]models.Distribution, error)
}

type OpenSourceInsightService interface {
	GetProject(ctx context.Context, projectID string) (dtos.OpenSourceInsightsProjectResponse, error)
	GetVersion(ctx context.Context, ecosystem, packageName, version string) (dtos.OpenSourceInsightsVersionResponse, error)
}

type ComponentProjectRepository interface {
	utils.Repository[string, models.ComponentProject, DB]
	FindAllOutdatedProjects(ctx context.Context, tx DB) ([]models.ComponentProject, error)
}

type ComponentService interface {
	GetAndSaveLicenseInformation(ctx context.Context, tx DB, assetVersion models.AssetVersion, artifactName *string, forceRefresh bool) ([]models.Component, error)
	RefreshComponentProjectInformation(ctx context.Context, project models.ComponentProject)
	GetLicense(ctx context.Context, component models.Component) (models.Component, error)
	FetchComponentProject(ctx context.Context, component models.Component) (models.Component, error)
	FetchInformationSources(ctx context.Context, tx DB, artifact *models.Artifact) ([]models.ComponentDependency, error)
	RemoveInformationSources(ctx context.Context, tx DB, artifact *models.Artifact, rootNodePurls []string) error
}

type CVERelationshipRepository interface {
	utils.Repository[string, models.CVERelationship, DB]
	GetAllRelationsForCVE(ctx context.Context, tx DB, targetCVEID string) ([]models.CVERelationship, error)
	GetAllRelationshipsForCVEBatch(ctx context.Context, tx DB, sourceCVEIDs []string) ([]models.CVERelationship, error)
	GetRelationshipsByTargetCVEBatch(ctx context.Context, tx DB, targetCVEIDs []string) ([]models.CVERelationship, error)
	FilterOutRelationsWithInvalidTargetCVE(ctx context.Context, tx DB) error
}

type LicenseRiskService interface {
	FindLicenseRisksInComponents(ctx context.Context, tx DB, assetVersion models.AssetVersion, components []models.Component, artifactName string) error
	UpdateLicenseRiskState(ctx context.Context, tx DB, userID string, licenseRisk *models.LicenseRisk, statusType string, justification string, mechanicalJustification dtos.MechanicalJustificationType) (models.VulnEvent, error)
	MakeFinalLicenseDecision(ctx context.Context, tx DB, vulnID, finalLicense, justification, userID string) error
}

type VulnDBImportService interface {
	ImportFromDiff(ctx context.Context, extraTableNameSuffix *string) error
	CleanupOrphanedTables(ctx context.Context) error
	CreateTablesWithSuffix(ctx context.Context, suffix string) error
	ExportDiffs(ctx context.Context, extraTableNameSuffix string) error
}

type AccessControl interface {
	HasAccess(ctx context.Context, subject string) (bool, error) // return error if couldnt be checked due to unauthorized access or other issues

	InheritRole(ctx context.Context, roleWhichGetsPermissions, roleWhichProvidesPermissions Role) error

	GetAllRoles(user string) []string

	GrantRole(ctx context.Context, subject string, role Role) error
	RevokeRole(ctx context.Context, subject string, role Role) error

	GrantRoleInProject(ctx context.Context, subject string, role Role, project string) error
	GrantRoleInAsset(ctx context.Context, subject string, role Role, asset string) error

	RevokeRoleInProject(ctx context.Context, subject string, role Role, project string) error
	RevokeRoleInAsset(ctx context.Context, subject string, role Role, asset string) error

	RevokeAllRolesInProjectForUser(ctx context.Context, user string, project string) error
	RevokeAllRolesInAssetForUser(ctx context.Context, user string, asset string) error

	InheritProjectRole(ctx context.Context, roleWhichGetsPermissions, roleWhichProvidesPermissions Role, project string) error
	InheritAssetRole(ctx context.Context, roleWhichGetsPermissions, roleWhichProvidesPermissions Role, asset string) error

	InheritProjectRolesAcrossProjects(ctx context.Context, roleWhichGetsPermissions, roleWhichProvidesPermissions ProjectRole) error

	LinkDomainAndProjectRole(ctx context.Context, domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions Role, project string) error
	LinkProjectAndAssetRole(ctx context.Context, projectRoleWhichGetsPermission, assetRoleWhichProvidesPermissions Role, project, asset string) error

	AllowRole(ctx context.Context, role Role, object Object, action []Action) error
	IsAllowed(ctx context.Context, subject string, object Object, action Action) (bool, error)

	IsAllowedInProject(ctx context.Context, project *models.Project, user string, object Object, action Action) (bool, error)
	IsAllowedInAsset(ctx context.Context, asset *models.Asset, user string, object Object, action Action) (bool, error)

	AllowRoleInProject(ctx context.Context, project string, role Role, object Object, action []Action) error
	AllowRoleInAsset(ctx context.Context, asset string, role Role, object Object, action []Action) error

	GetAllProjectsForUser(user string) ([]string, error)
	GetAllAssetsForUser(user string) ([]string, error)

	GetOwnerOfOrganization() (string, error)

	GetAllMembersOfOrganization() ([]string, error)

	GetAllMembersOfProject(projectID string) ([]string, error)
	GetAllMembersOfAsset(projectID string) ([]string, error)

	GetDomainRole(user string) (Role, error)
	GetProjectRole(user string, project string) (Role, error)
	GetAssetRole(user string, asset string) (Role, error)

	GetExternalEntityProviderID() *string
}

type RBACProvider interface {
	GetDomainRBAC(domain string) AccessControl
	DomainsOfUser(user string) ([]string, error)
}

type RBACMiddleware = func(obj Object, act Action) echo.MiddlewareFunc

type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleGuest  Role = "guest"

	// this is mainly for backwards compatibility - and to have a default value
	// noone should ever have the role unknown. This happens, if you logged into devguard before the "real permission sync" - not forwarding permission sync
	// was added
	RoleUnknown Role = "unknown"
)

type Action string

const (
	ActionCreate Action = "create"
	ActionRead   Action = "read"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

type TrustedEntityRepository interface {
	utils.Repository[uuid.UUID, models.TrustedEntity, DB]
	UpsertOrganizationTrust(ctx context.Context, tx DB, organizationID uuid.UUID, trustScore float64) error
	UpsertProjectTrust(ctx context.Context, tx DB, projectID uuid.UUID, trustScore float64) error
	GetOrganizationTrust(ctx context.Context, tx DB, organizationID uuid.UUID) (*models.TrustedEntity, error)
	GetProjectTrust(ctx context.Context, tx DB, projectID uuid.UUID) (*models.TrustedEntity, error)
	DeleteOrganizationTrust(ctx context.Context, tx DB, organizationID uuid.UUID) error
	DeleteProjectTrust(ctx context.Context, tx DB, projectID uuid.UUID) error
	ListAllTrustedEntities(ctx context.Context, tx DB) ([]models.TrustedEntity, error)
}

type Object string

const (
	ObjectProject      Object = "project"
	ObjectAsset        Object = "asset"
	ObjectUser         Object = "user"
	ObjectOrganization Object = "organization"
)

type ProjectRole struct {
	Project string
	Role    Role
}

type ScannerType string

const (
	VexReport     ScannerType = "vex-report"
	ScaScanner    ScannerType = "source-scanner"
	ContainerScan ScannerType = "container-scan"
	TestScanner   ScannerType = "test-scanner"
)
