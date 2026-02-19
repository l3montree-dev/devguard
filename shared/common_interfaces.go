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
	RunDaemonPipelineForAsset(assetID uuid.UUID) error
	RunAssetPipeline(forceAll bool)
	UpdateFixedVersions() error
	UpdateVulnDB() error
	UpdateOpenSourceInsightInformation() error

	Start()
}

type LeaderElector interface {
	IsLeader() bool
}
type ReleaseService interface {
	ListByProject(projectID uuid.UUID) ([]models.Release, error)
	ListByProjectPaged(projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.Release], error)
	Read(id uuid.UUID) (models.Release, error)
	ReadRecursive(id uuid.UUID) (models.Release, error)
	Create(r *models.Release) error
	Update(r *models.Release) error
	Delete(id uuid.UUID) error
	AddItem(item *models.ReleaseItem) error
	RemoveItem(id uuid.UUID) error
	ListCandidates(projectID uuid.UUID, releaseID *uuid.UUID) ([]models.Artifact, []models.Release, error)
}

type PersonalAccessTokenService interface {
	VerifyRequestSignature(req *http.Request) (string, string, error)
	RevokeByPrivateKey(privKey string) error
	ToModel(request dtos.PatCreateRequest, userID string) models.PAT
}

type CSAFService interface {
	GetVexFromCsafProvider(purl packageurl.PackageURL, domain string) (*cyclonedx.BOM, error)
}

type SBOMScanner interface {
	Scan(bom *normalize.SBOMGraph) ([]models.VulnInPackage, error)
}
type ProjectRepository interface {
	Read(projectID uuid.UUID) (models.Project, error)
	ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error)
	ReadBySlugUnscoped(organizationID uuid.UUID, slug string) (models.Project, error)
	Update(tx DB, project *models.Project) error
	Delete(tx DB, projectID uuid.UUID) error
	Create(tx DB, project *models.Project) error
	Activate(tx DB, projectID uuid.UUID) error
	RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error)
	GetDirectChildProjects(projectID uuid.UUID) ([]models.Project, error)
	GetByOrgID(organizationID uuid.UUID) ([]models.Project, error)
	GetProjectByAssetID(assetID uuid.UUID) (models.Project, error)
	List(idSlice []uuid.UUID, parentID *uuid.UUID, organizationID uuid.UUID) ([]models.Project, error)
	ListPaged(projectIDs []uuid.UUID, parentID *uuid.UUID, orgID uuid.UUID, pageInfo PageInfo, search string) (Paged[models.Project], error)
	EnablePolicyForProject(tx DB, projectID uuid.UUID, policyID uuid.UUID) error
	DisablePolicyForProject(tx DB, projectID uuid.UUID, policyID uuid.UUID) error
	Upsert(projects *[]*models.Project, conflictingColumns []clause.Column, toUpdate []string) error
	EnableCommunityManagedPolicies(tx DB, projectID uuid.UUID) error
	UpsertSplit(tx DB, externalProviderID string, projects []*models.Project) ([]*models.Project, []*models.Project, error)
}

type Verifier interface {
	VerifyRequestSignature(req *http.Request) (string, string, error)
}

type PolicyRepository interface {
	utils.Repository[uuid.UUID, models.Policy, DB]
	FindByProjectID(projectID uuid.UUID) ([]models.Policy, error)
	FindByOrganizationID(organizationID uuid.UUID) ([]models.Policy, error)
	FindCommunityManagedPolicies() ([]models.Policy, error)
}

type AssetRepository interface {
	utils.Repository[uuid.UUID, models.Asset, DB]
	GetAllowedAssetsByProjectID(allowedAssetIDs []string, projectID uuid.UUID) ([]models.Asset, error)
	GetByProjectID(projectID uuid.UUID) ([]models.Asset, error)
	GetByOrgID(organizationID uuid.UUID) ([]models.Asset, error)
	FindByName(name string) (models.Asset, error)
	FindAssetByExternalProviderID(externalEntityProviderID string, externalEntityID string) (*models.Asset, error)
	GetFQNByID(id uuid.UUID) (string, error)
	ReadBySlug(projectID uuid.UUID, slug string) (models.Asset, error)
	GetAssetIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error)
	Update(tx DB, asset *models.Asset) error
	ReadBySlugUnscoped(projectID uuid.UUID, slug string) (models.Asset, error)
	GetAllAssetsFromDB() ([]models.Asset, error)
	Delete(tx DB, id uuid.UUID) error
	ReadWithAssetVersions(assetID uuid.UUID) (models.Asset, error)
	GetAssetsWithVulnSharingEnabled(orgID uuid.UUID) ([]models.Asset, error)
}

type AttestationRepository interface {
	utils.Repository[string, models.Attestation, DB]
	GetByAssetID(assetID uuid.UUID) ([]models.Attestation, error)
	GetByAssetVersionAndAssetID(assetID uuid.UUID, assetVersion string) ([]models.Attestation, error)
}

type ArtifactRepository interface {
	utils.Repository[string, models.Artifact, DB]
	GetByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string) ([]models.Artifact, error)
	ReadArtifact(name string, assetVersionName string, assetID uuid.UUID) (models.Artifact, error)
	DeleteArtifact(tx DB, assetID uuid.UUID, assetVersionName string, artifactName string) error
	GetAllArtifactAffectedByDependencyVuln(tx DB, vulnID string) ([]models.Artifact, error)
	GetByAssetVersions(assetID uuid.UUID, assetVersionNames []string) ([]models.Artifact, error)
}

type ReleaseRepository interface {
	utils.Repository[uuid.UUID, models.Release, DB]
	GetByProjectID(projectID uuid.UUID) ([]models.Release, error)
	ReadWithItems(id uuid.UUID) (models.Release, error)
	ReadRecursive(id uuid.UUID) (models.Release, error)
	GetByProjectIDPaged(tx DB, projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.Release], error)
	CreateReleaseItem(tx DB, item *models.ReleaseItem) error
	DeleteReleaseItem(tx DB, id uuid.UUID) error
	GetCandidateItemsForRelease(projectID uuid.UUID, releaseID *uuid.UUID) ([]models.Artifact, []models.Release, error)
}

type CveRepository interface {
	utils.Repository[string, models.CVE, DB]
	FindByID(id string) (models.CVE, error)
	GetLastModDate() (time.Time, error)
	GetAllCVEsID() ([]string, error)
	Save(tx DB, cve *models.CVE) error
	SaveCveAffectedComponents(tx DB, cveID string, affectedComponentHashes []string) error
	FindCVE(tx DB, id string) (models.CVE, error)
	FindCVEs(tx DB, ids []string) ([]models.CVE, error)
	FindAllListPaged(tx DB, pageInfo PageInfo, filter []FilterQuery, sort []SortQuery) (Paged[models.CVE], error)
	CreateCVEWithConflictHandling(tx DB, cve *models.CVE) error
	CreateCVEAffectedComponentsEntries(tx DB, cve *models.CVE, components []models.AffectedComponent) error
	UpdateEpssBatch(tx DB, batch []models.CVE) error
	UpdateCISAKEVBatch(tx DB, batch []models.CVE) error
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
	utils.Repository[string, models.AffectedComponent, DB]
	GetAllAffectedComponentsID() ([]string, error)
	Save(tx DB, affectedComponent *models.AffectedComponent) error
	SaveBatch(tx DB, affectedPkgs []models.AffectedComponent) error
	DeleteAll(tx DB, ecosystem string) error
	CreateAffectedComponentsUsingUnnest(tx DB, components []models.AffectedComponent) error
}

type MaliciousPackageChecker interface {
	DownloadAndProcessDB() error
	IsMalicious(ecosystem, packageName, version string) (bool, *dtos.OSV)
}

type ComponentRepository interface {
	utils.Repository[string, models.Component, DB]
	LoadComponents(tx DB, assetVersionName string, assetID uuid.UUID) ([]models.ComponentDependency, error)
	LoadComponentsWithProject(tx DB, overwrittenLicenses []models.LicenseRisk, assetVersionName string, assetID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.ComponentDependency], error)
	SearchComponentOccurrencesByProject(tx DB, projectIDs []uuid.UUID, pageInfo PageInfo, search string) (Paged[models.ComponentOccurrence], error)
	SaveBatch(tx DB, components []models.Component) error
	FindByPurl(tx DB, purl string) (models.Component, error)
	HandleStateDiff(tx DB, assetVersion models.AssetVersion, wholeAssetGraph *normalize.SBOMGraph, diff normalize.GraphDiff) error
	CreateComponents(tx DB, components []models.ComponentDependency) error
	FetchInformationSources(artifact *models.Artifact) ([]models.ComponentDependency, error)
	RemoveInformationSources(artifact *models.Artifact, rootNodePurls []string) error
}

type DependencyVulnRepository interface {
	utils.Repository[string, models.DependencyVuln, DB]
	GetByAssetID(tx DB, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetAllVulnsByAssetID(tx DB, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetAllVulnsByAssetIDWithTicketIDs(tx DB, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetDependencyVulnByCVEIDAndAssetID(tx DB, cveID string, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetAllOpenVulnsByAssetVersionNameAndAssetID(tx DB, artifactName *string, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetDependencyVulnsByAssetVersion(tx DB, assetVersionName string, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error)
	GetByAssetVersionPaged(tx DB, assetVersionName string, assetID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], map[string]int, error)
	GetDefaultDependencyVulnsByOrgIDPaged(tx DB, userAllowedProjectIds []string, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)
	GetDefaultDependencyVulnsByProjectIDPaged(tx DB, projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)
	GetDependencyVulnsByAssetVersionPagedAndFlat(tx DB, assetVersionName string, assetVersionID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.DependencyVuln], error)
	ListByAssetAndAssetVersion(assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetDependencyVulnsByPurl(tx DB, purls []string) ([]models.DependencyVuln, error)
	ApplyAndSave(tx DB, dependencyVuln *models.DependencyVuln, vulnEvent *models.VulnEvent) error
	GetDependencyVulnsByDefaultAssetVersion(tx DB, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error)
	ListUnfixedByAssetAndAssetVersion(tx DB, assetVersionName string, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error)
	GetHintsInOrganizationForVuln(tx DB, orgID uuid.UUID, pURL string, cveID string) (dtos.DependencyVulnHints, error)
	GetAllByAssetIDAndState(tx DB, assetID uuid.UUID, state dtos.VulnState, durationSinceStateChange time.Duration) ([]models.DependencyVuln, error)
	GetDependencyVulnsByOtherAssetVersions(tx DB, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetAllVulnsByArtifact(tx DB, artifact models.Artifact) ([]models.DependencyVuln, error)
	GetAllVulnsForTagsAndDefaultBranchInAsset(tx DB, assetID uuid.UUID, excludedStates []dtos.VulnState) ([]models.DependencyVuln, error)
	// regardless of path. Used for applying status changes to all instances of a CVE+component combination.
	FindByCVEAndComponentPurl(tx DB, assetID uuid.UUID, cveID string, componentPurl string) ([]models.DependencyVuln, error)
}

type FirstPartyVulnRepository interface {
	utils.Repository[string, models.FirstPartyVuln, DB]
	SaveBatch(tx DB, vulns []models.FirstPartyVuln) error
	Save(tx DB, vuln *models.FirstPartyVuln) error
	Transaction(txFunc func(DB) error) error
	Begin() DB
	GetDefaultFirstPartyVulnsByProjectIDPaged(tx DB, projectID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVuln], error)
	GetDefaultFirstPartyVulnsByOrgIDPaged(tx DB, userAllowedProjectIds []string, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVuln], error)
	GetByAssetID(tx DB, assetID uuid.UUID) ([]models.FirstPartyVuln, error)
	GetByAssetVersionPaged(tx DB, assetVersionName string, assetID uuid.UUID, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.FirstPartyVuln], map[string]int, error)
	ListByScanner(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVuln, error)
	ApplyAndSave(tx DB, dependencyVuln *models.FirstPartyVuln, vulnEvent *models.VulnEvent) error
	GetByAssetVersion(tx DB, assetVersionName string, assetID uuid.UUID) ([]models.FirstPartyVuln, error)
	GetFirstPartyVulnsByOtherAssetVersions(tx DB, assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVuln, error)
	ListUnfixedByAssetAndAssetVersionAndScanner(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVuln, error)
}

type LicenseRiskRepository interface {
	utils.Repository[string, models.LicenseRisk, DB]
	GetByAssetID(tx DB, assetID uuid.UUID) ([]models.LicenseRisk, error)
	GetAllLicenseRisksForAssetVersionPaged(tx DB, assetID uuid.UUID, assetVersionName string, pageInfo PageInfo, search string, filter []FilterQuery, sort []SortQuery) (Paged[models.LicenseRisk], error)
	GetAllLicenseRisksForAssetVersion(assetID uuid.UUID, assetVersionName string) ([]models.LicenseRisk, error)
	GetLicenseRisksByOtherAssetVersions(tx DB, assetVersionName string, assetID uuid.UUID) ([]models.LicenseRisk, error)
	GetAllOverwrittenLicensesForAssetVersion(assetID uuid.UUID, assetVersionName string) ([]models.LicenseRisk, error)
	MaybeGetLicenseOverwriteForComponent(assetID uuid.UUID, assetVersionName string, pURL packageurl.PackageURL) (models.LicenseRisk, error)
	DeleteByComponentPurl(assetID uuid.UUID, assetVersionName string, purl packageurl.PackageURL) error
	ListByArtifactName(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.LicenseRisk, error)
	ApplyAndSave(tx DB, licenseRisk *models.LicenseRisk, vulnEvent *models.VulnEvent) error
}

type InTotoLinkRepository interface {
	utils.Repository[uuid.UUID, models.InTotoLink, DB]
	FindByAssetAndSupplyChainID(assetID uuid.UUID, supplyChainID string) ([]models.InTotoLink, error)
	Save(tx DB, model *models.InTotoLink) error
	FindBySupplyChainID(supplyChainID string) ([]models.InTotoLink, error)
}

type PersonalAccessTokenRepository interface {
	utils.Repository[uuid.UUID, models.PAT, DB]
	GetByFingerprint(fingerprint string) (models.PAT, error)
	FindByUserIDs(userID []uuid.UUID) ([]models.PAT, error)
	ListByUserID(userID string) ([]models.PAT, error)
	DeleteByFingerprint(fingerprint string) error
	MarkAsLastUsedNow(fingerprint string) error
}

type SupplyChainRepository interface {
	utils.Repository[uuid.UUID, models.SupplyChain, DB]
	FindByDigest(digest string) ([]models.SupplyChain, error)
	FindBySupplyChainID(supplyChainID string) ([]models.SupplyChain, error)
	PercentageOfVerifiedSupplyChains(assetVersionName string, assetID uuid.UUID) (float64, error)
}

type VEXRuleRepository interface {
	GetDB(db DB) DB
	FindByAssetVersion(db DB, assetID uuid.UUID, assetVersionName string) ([]models.VEXRule, error)
	FindByAssetVersionPaged(db DB, assetID uuid.UUID, assetVersionName string, pageInfo PageInfo, search string, filterQuery []FilterQuery, sortQuery []SortQuery) (Paged[models.VEXRule], error)
	FindByID(db DB, id string) (models.VEXRule, error)
	FindByAssetAndVexSource(db DB, assetID uuid.UUID, vexSource string) ([]models.VEXRule, error)
	Create(db DB, rule *models.VEXRule) error
	Upsert(db DB, rule *models.VEXRule) error
	UpsertBatch(db DB, rules []models.VEXRule) error
	Update(db DB, rule *models.VEXRule) error
	Delete(db DB, rule models.VEXRule) error
	DeleteBatch(db DB, rules []models.VEXRule) error
	DeleteByAssetVersion(db DB, assetID uuid.UUID, assetVersionName string) error
	Begin() DB
	FindByAssetVersionAndCVE(db DB, assetID uuid.UUID, assetVersionName string, cveID string) ([]models.VEXRule, error)
}

type OrganizationRepository interface {
	utils.Repository[uuid.UUID, models.Org, DB]
	ReadBySlug(slug string) (models.Org, error)
	Update(tx DB, organization *models.Org) error
	ContentTree(orgID uuid.UUID, projects []string) []any // returns project dtos as values - including fetched assets
	GetOrgByID(id uuid.UUID) (models.Org, error)
	GetOrgsWithVulnSharingAssets() ([]models.Org, error)
}

type OrgService interface {
	CreateOrganization(ctx Context, organization *models.Org) error
	ReadBySlug(slug string) (*models.Org, error)
}

type InvitationRepository interface {
	Save(tx DB, invitation *models.Invitation) error
	FindByCode(code string) (models.Invitation, error)
	Delete(tx DB, id uuid.UUID) error
}

type ExternalReferenceRepository interface {
	utils.Repository[uuid.UUID, models.ExternalReference, DB]
	FindByAssetVersion(tx DB, assetID uuid.UUID, assetVersionName string) ([]models.ExternalReference, error)
}

type ExternalEntityProviderService interface {
	RefreshExternalEntityProviderProjects(ctx Context, org models.Org, user string) error
	TriggerOrgSync(c Context) error
	SyncOrgs(c Context) ([]*models.Org, error)
	TriggerSync(c echo.Context) error
}

type ProjectService interface {
	ReadBySlug(ctx Context, organizationID uuid.UUID, slug string) (models.Project, error)
	ListAllowedProjects(ctx Context) ([]models.Project, error)
	ListAllowedProjectsPaged(c Context) (Paged[models.Project], error)
	ListProjectsByOrganizationID(organizationID uuid.UUID) ([]models.Project, error)
	RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error)
	GetDirectChildProjects(projectID uuid.UUID) ([]models.Project, error)
	CreateProject(ctx Context, project *models.Project) error
	BootstrapProject(rbac AccessControl, project *models.Project) error
}

type InTotoVerifierService interface {
	VerifySupplyChainWithOutputDigest(supplyChainID string, digest string) (bool, error)
	VerifySupplyChain(supplyChainID string) (bool, error)
	VerifySupplyChainByDigestOnly(digest string) (bool, error)
	HexPublicKeyToInTotoKey(hexPubKey string) (toto.Key, error)
}

type AssetService interface {
	UpdateAssetRequirements(asset models.Asset, responsible string, justification string) error
	GetCVSSBadgeSVG(results []models.ArtifactRiskHistory) string
	CreateAsset(rbac AccessControl, currentUserID string, asset models.Asset) (*models.Asset, error)
	BootstrapAsset(rbac AccessControl, asset *models.Asset) error
}
type ArtifactService interface {
	GetArtifactsByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string) ([]models.Artifact, error)
	SaveArtifact(artifact *models.Artifact) error
	DeleteArtifact(assetID uuid.UUID, assetVersionName string, artifactName string) error
	ReadArtifact(name string, assetVersionName string, assetID uuid.UUID) (models.Artifact, error)
}

type DependencyVulnService interface {
	RecalculateRawRiskAssessment(tx DB, userID string, dependencyVulns []models.DependencyVuln, justification string, asset models.Asset) ([]models.DependencyVuln, error)
	UserFixedDependencyVulns(tx DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset) error
	UserDetectedDependencyVulns(tx DB, artifactName string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset) error
	UserDetectedExistingVulnOnDifferentBranch(tx DB, artifactName string, dependencyVulns []statemachine.BranchVulnMatch[*models.DependencyVuln], assetVersion models.AssetVersion, asset models.Asset) error
	UserDetectedDependencyVulnInAnotherArtifact(tx DB, vulnerabilities []models.DependencyVuln, artifactName string) error
	UserDidNotDetectDependencyVulnInArtifactAnymore(tx DB, vulnerabilities []models.DependencyVuln, artifactName string) error
	CreateVulnEventAndApply(tx DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, status dtos.VulnEventType, justification string, mechanicalJustification dtos.MechanicalJustificationType, assetVersionName string) (models.VulnEvent, error)
	SyncIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, vulnList []models.DependencyVuln) error
	SyncAllIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion) error
}

type AssetVersionService interface {
	BuildVeX(frontendURL string, orgName string, orgSlug string, projectSlug string, asset models.Asset, assetVersion models.AssetVersion, artifactName string, dependencyVulns []models.DependencyVuln) *normalize.SBOMGraph
	GetAssetVersionsByAssetID(assetID uuid.UUID) ([]models.AssetVersion, error)
	UpdateSBOM(tx DB, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifactName string, sbom *normalize.SBOMGraph) (*normalize.SBOMGraph, error)
	BuildOpenVeX(asset models.Asset, assetVersion models.AssetVersion, organizationSlug string, dependencyVulns []models.DependencyVuln) vex.VEX
	LoadFullSBOMGraph(assetVersion models.AssetVersion) (*normalize.SBOMGraph, error)
}

type AssetVersionRepository interface {
	All() ([]models.AssetVersion, error)
	Read(assetVersionName string, assetID uuid.UUID) (models.AssetVersion, error)
	GetDB(DB) DB
	Begin() DB
	Delete(tx DB, assetVersion *models.AssetVersion) error
	Save(tx DB, assetVersion *models.AssetVersion) error
	GetAssetVersionsByAssetID(tx DB, assetID uuid.UUID) ([]models.AssetVersion, error)
	GetAssetVersionsByAssetIDWithArtifacts(tx DB, assetID uuid.UUID) ([]models.AssetVersion, error)
	GetDefaultAssetVersionsByProjectID(projectID uuid.UUID) ([]models.AssetVersion, error)
	GetDefaultAssetVersionsByProjectIDs(projectIDs []uuid.UUID) ([]models.AssetVersion, error)
	FindOrCreate(assetVersionName string, assetID uuid.UUID, tag bool, defaultBranchName *string) (models.AssetVersion, error)
	ReadBySlug(assetID uuid.UUID, slug string) (models.AssetVersion, error)
	GetDefaultAssetVersion(assetID uuid.UUID) (models.AssetVersion, error)
	GetAllTagsAndDefaultBranchForAsset(tx DB, assetID uuid.UUID) ([]models.AssetVersion, error)
	UpdateAssetDefaultBranch(assetID uuid.UUID, defaultBranch string) error
	DeleteOldAssetVersions(day int) (int64, error)
	DeleteOldAssetVersionsOfAsset(assetID uuid.UUID, day int) (int64, error)
}

type FirstPartyVulnService interface {
	UserFixedFirstPartyVulns(tx DB, userID string, firstPartyVulns []models.FirstPartyVuln) error
	UserDetectedFirstPartyVulns(tx DB, userID string, scannerID string, firstPartyVulns []models.FirstPartyVuln) error
	UserDetectedExistingFirstPartyVulnOnDifferentBranch(tx DB, scannerID string, firstPartyVulns []statemachine.BranchVulnMatch[*models.FirstPartyVuln], assetVersion models.AssetVersion, asset models.Asset) error
	UpdateFirstPartyVulnState(tx DB, userID string, firstPartyVuln *models.FirstPartyVuln, statusType string, justification string, mechanicalJustification dtos.MechanicalJustificationType) (models.VulnEvent, error)
	SyncIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, vulnList []models.FirstPartyVuln) error
	SyncAllIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion) error
}

type ScanService interface {
	ScanNormalizedSBOM(tx DB, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, normalizedBom *normalize.SBOMGraph, userID string) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, error)
	HandleScanResult(tx DB, org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sbom *normalize.SBOMGraph, vulns []models.VulnInPackage, artifactName string, userID string) (opened []models.DependencyVuln, closed []models.DependencyVuln, newState []models.DependencyVuln, err error)
	HandleFirstPartyVulnResult(org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sarifScan sarif.SarifSchema210Json, scannerID string, userID string) ([]models.FirstPartyVuln, []models.FirstPartyVuln, []models.FirstPartyVuln, error)
	FetchSbomsFromUpstream(artifactName string, ref string, upstreamURLs []string, keepOriginalSbomRootComponent bool) ([]*normalize.SBOMGraph, []string, []dtos.ExternalReferenceError)
	FetchVexFromUpstream(upstreamURLs []models.ExternalReference) ([]*normalize.VexReport, []models.ExternalReference, []models.ExternalReference)
	RunArtifactSecurityLifecycle(tx DB, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, userID string) (*normalize.SBOMGraph, []*normalize.VexReport, []models.DependencyVuln, error)
}

type ConfigRepository interface {
	Save(tx DB, config *models.Config) error
	GetDB(tx DB) DB
}

type VEXRuleService interface {
	Begin() DB
	Create(tx DB, rule *models.VEXRule) error
	Update(tx DB, rule *models.VEXRule) error
	Delete(tx DB, rule models.VEXRule) error
	DeleteByAssetVersion(tx DB, assetID uuid.UUID, assetVersionName string) error
	FindByAssetVersion(tx DB, assetID uuid.UUID, assetVersionName string) ([]models.VEXRule, error)
	FindByAssetVersionPaged(tx DB, assetID uuid.UUID, assetVersionName string, pageInfo PageInfo, search string, filterQuery []FilterQuery, sortQuery []SortQuery) (Paged[models.VEXRule], error)
	ApplyRulesToExistingVulns(tx DB, rules []models.VEXRule) ([]models.DependencyVuln, error)
	ApplyRulesToExistingVulnsForce(tx DB, rules []models.VEXRule) ([]models.DependencyVuln, error)
	ApplyRulesToExisting(tx DB, rules []models.VEXRule, vulns []models.DependencyVuln) ([]models.DependencyVuln, error)
	ApplyRulesToExistingForce(tx DB, rules []models.VEXRule, vulns []models.DependencyVuln) ([]models.DependencyVuln, error)
	IngestVEX(tx DB, asset models.Asset, assetVersion models.AssetVersion, vexReport *normalize.VexReport) error
	IngestVexes(tx DB, asset models.Asset, assetVersion models.AssetVersion, vexReports []*normalize.VexReport) error
	CountMatchingVulns(tx DB, rule models.VEXRule) (int, error)
	CountMatchingVulnsForRules(tx DB, rules []models.VEXRule) (map[string]int, error)
	FindByID(tx DB, id string) (models.VEXRule, error)
	FindByAssetVersionAndCVE(tx DB, assetID uuid.UUID, assetVersionName string, cveID string) ([]models.VEXRule, error)
	FindByAssetVersionAndVulnID(tx DB, assetID uuid.UUID, assetVersionName string, vulnID string) ([]models.VEXRule, error)
}

type VulnEventRepository interface {
	SaveBatch(db DB, events []models.VulnEvent) error
	SaveBatchBestEffort(db DB, events []models.VulnEvent) error
	Save(db DB, event *models.VulnEvent) error
	ReadAssetEventsByVulnID(vulnID string, vulnType dtos.VulnType) ([]models.VulnEventDetail, error)
	ReadEventsByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string, pageInfo PageInfo, filter []FilterQuery) (Paged[models.VulnEventDetail], error)
	GetSecurityRelevantEventsForVulnIDs(tx DB, vulnIDs []string) ([]models.VulnEvent, error)
	GetLastEventBeforeTimestamp(tx DB, vulnID string, time time.Time) (models.VulnEvent, error)
	DeleteEventByID(tx DB, eventID string) error
	HasAccessToEvent(assetID uuid.UUID, eventID string) (bool, error)
}

type GithubAppInstallationRepository interface {
	Save(tx DB, model *models.GithubAppInstallation) error
	Read(installationID int) (models.GithubAppInstallation, error)
	FindByOrganizationID(orgID uuid.UUID) ([]models.GithubAppInstallation, error)
	Delete(tx DB, installationID int) error
}

type VulnRepository interface {
	FindByTicketID(tx DB, ticketID string) (models.Vuln, error)
	Save(db DB, vuln *models.Vuln) error
	Transaction(fn func(tx DB) error) error
	GetOrgFromVuln(vuln models.Vuln) (models.Org, error)
	ApplyAndSave(tx DB, dependencyVuln models.Vuln, vulnEvent *models.VulnEvent) error
}

type ExternalUserRepository interface {
	Save(db DB, user *models.ExternalUser) error
	GetDB(tx DB) DB
	FindByOrgID(tx DB, orgID uuid.UUID) ([]models.ExternalUser, error)
}

type JiraIntegrationRepository interface {
	Save(tx DB, model *models.JiraIntegration) error
	Read(id uuid.UUID) (models.JiraIntegration, error)
	FindByOrganizationID(orgID uuid.UUID) ([]models.JiraIntegration, error)
	Delete(tx DB, id uuid.UUID) error
	GetClientByIntegrationID(integrationID uuid.UUID) (models.JiraIntegration, error)
}

type WebhookIntegrationRepository interface {
	Save(tx DB, model *models.WebhookIntegration) error
	Read(id uuid.UUID) (models.WebhookIntegration, error)
	FindByOrgIDAndProjectID(orgID uuid.UUID, projectID uuid.UUID) ([]models.WebhookIntegration, error)
	Delete(tx DB, id uuid.UUID) error
	GetClientByIntegrationID(integrationID uuid.UUID) (models.WebhookIntegration, error)
	GetProjectWebhooks(orgID uuid.UUID, projectID uuid.UUID) ([]models.WebhookIntegration, error)
}

type GitlabIntegrationRepository interface {
	Save(tx DB, model *models.GitLabIntegration) error
	Read(id uuid.UUID) (models.GitLabIntegration, error)
	FindByOrganizationID(orgID uuid.UUID) ([]models.GitLabIntegration, error)
	Delete(tx DB, id uuid.UUID) error
}

type GitLabOauth2TokenRepository interface {
	Save(tx DB, model ...*models.GitLabOauth2Token) error
	FindByUserIDAndProviderID(userID string, providerID string) (*models.GitLabOauth2Token, error)
	FindByUserID(userID string) ([]models.GitLabOauth2Token, error)
	Delete(tx DB, tokens []models.GitLabOauth2Token) error
	DeleteByUserIDAndProviderID(userID string, providerID string) error
	CreateIfNotExists(tokens []*models.GitLabOauth2Token) error
}

type ConfigService interface {
	// retrieves the value for the given key and marshals it into v
	GetJSONConfig(key string, v any) error
	SetJSONConfig(key string, v any) error
}

type StatisticsRepository interface {
	TimeTravelDependencyVulnState(artifactName *string, assetVersionName *string, assetID uuid.UUID, time time.Time) ([]models.DependencyVuln, error)
	AverageFixingTime(artifactNam *string, assetVersionName string, assetID uuid.UUID, riskIntervalStart, riskIntervalEnd float64) (time.Duration, error)
	// AverageFixingTimeForRelease computes average fixing time across all artifacts included in a release tree
	AverageFixingTimeForRelease(releaseID uuid.UUID, riskIntervalStart, riskIntervalEnd float64) (time.Duration, error)
	// CVSS-based average fixing time methods
	AverageFixingTimeByCvss(artifactName *string, assetVersionName string, assetID uuid.UUID, cvssIntervalStart, cvssIntervalEnd float64) (time.Duration, error)
	AverageFixingTimeByCvssForRelease(releaseID uuid.UUID, cvssIntervalStart, cvssIntervalEnd float64) (time.Duration, error)
	CVESWithKnownExploitsInAssetVersion(assetVersion models.AssetVersion) ([]models.CVE, error)
	VulnClassificationByOrg(orgID uuid.UUID) (dtos.Distribution, error)
	GetOrgStructureDistribution(orgID uuid.UUID) (dtos.OrgStructureDistribution, error)
}

type ArtifactRiskHistoryRepository interface {
	// artifactName if non-nil restricts the history to a single artifact (artifactName + assetVersionName + assetID)
	GetRiskHistory(artifactName *string, assetVersionName string, assetID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error)
	// GetRiskHistoryByRelease collects artifact risk histories for all artifacts included in a release tree
	GetRiskHistoryByRelease(releaseID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error)
	UpdateRiskAggregation(assetRisk *models.ArtifactRiskHistory) error
}

type ProjectRiskHistoryRepository interface {
	GetRiskHistory(projectID uuid.UUID, start, end time.Time) ([]models.ProjectRiskHistory, error)
	UpdateRiskAggregation(projectRisk *models.ProjectRiskHistory) error
}

type StatisticsService interface {
	UpdateArtifactRiskAggregation(artifact *models.Artifact, assetID uuid.UUID, begin time.Time, end time.Time) error
	GetAverageFixingTime(artifactName *string, assetVersionName string, assetID uuid.UUID, severity string) (time.Duration, error)
	GetArtifactRiskHistory(artifactName *string, assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistory, error)
	// Release scoped statistics
	GetReleaseRiskHistory(releaseID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistory, error)
	GetAverageFixingTimeForRelease(releaseID uuid.UUID, severity string) (time.Duration, error)
	// CVSS-based average fixing time methods
	GetAverageFixingTimeByCvss(artifactName *string, assetVersionName string, assetID uuid.UUID, severity string) (time.Duration, error)
	GetAverageFixingTimeByCvssForRelease(releaseID uuid.UUID, severity string) (time.Duration, error)
	GetComponentRisk(artifactName *string, assetVersionName string, assetID uuid.UUID) (map[string]models.Distribution, error)
}

type OpenSourceInsightService interface {
	GetProject(ctx context.Context, projectID string) (dtos.OpenSourceInsightsProjectResponse, error)
	GetVersion(ctx context.Context, ecosystem, packageName, version string) (dtos.OpenSourceInsightsVersionResponse, error)
}

type ComponentProjectRepository interface {
	utils.Repository[string, models.ComponentProject, DB]
	FindAllOutdatedProjects() ([]models.ComponentProject, error)
}

type ComponentService interface {
	GetAndSaveLicenseInformation(tx DB, assetVersion models.AssetVersion, artifactName *string, forceRefresh bool) ([]models.Component, error)
	RefreshComponentProjectInformation(project models.ComponentProject)
	GetLicense(component models.Component) (models.Component, error)
	FetchInformationSources(artifact *models.Artifact) ([]models.ComponentDependency, error)
	RemoveInformationSources(artifact *models.Artifact, rootNodePurls []string) error
}

type CVERelationshipRepository interface {
	utils.Repository[string, models.CVERelationship, DB]
	GetAllRelationsForCVE(tx DB, targetCVEID string) ([]models.CVERelationship, error)
	GetAllRelationshipsForCVEBatch(tx DB, sourceCVEIDs []string) ([]models.CVERelationship, error)
	GetRelationshipsByTargetCVEBatch(tx DB, targetCVEIDs []string) ([]models.CVERelationship, error)
	FilterOutRelationsWithInvalidTargetCVE(tx DB) error
}

type LicenseRiskService interface {
	FindLicenseRisksInComponents(assetVersion models.AssetVersion, components []models.Component, artifactName string) error
	UpdateLicenseRiskState(tx DB, userID string, licenseRisk *models.LicenseRisk, statusType string, justification string, mechanicalJustification dtos.MechanicalJustificationType) (models.VulnEvent, error)
	MakeFinalLicenseDecision(vulnID, finalLicense, justification, userID string) error
}

type VulnDBImportService interface {
	ImportFromDiff(extraTableNameSuffix *string) error
	CleanupOrphanedTables() error
	CreateTablesWithSuffix(suffix string) error
	ExportDiffs(extraTableNameSuffix string) error
}

type AccessControl interface {
	HasAccess(subject string) (bool, error) // return error if couldnt be checked due to unauthorized access or other issues

	InheritRole(roleWhichGetsPermissions, roleWhichProvidesPermissions Role) error

	GetAllRoles(user string) []string

	GrantRole(subject string, role Role) error
	RevokeRole(subject string, role Role) error

	GrantRoleInProject(subject string, role Role, project string) error
	GrantRoleInAsset(subject string, role Role, asset string) error

	RevokeRoleInProject(subject string, role Role, project string) error
	RevokeRoleInAsset(subject string, role Role, asset string) error

	RevokeAllRolesInProjectForUser(user string, project string) error
	RevokeAllRolesInAssetForUser(user string, asset string) error

	InheritProjectRole(roleWhichGetsPermissions, roleWhichProvidesPermissions Role, project string) error
	InheritAssetRole(roleWhichGetsPermissions, roleWhichProvidesPermissions Role, asset string) error

	InheritProjectRolesAcrossProjects(roleWhichGetsPermissions, roleWhichProvidesPermissions ProjectRole) error

	LinkDomainAndProjectRole(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions Role, project string) error
	LinkProjectAndAssetRole(projectRoleWhichGetsPermission, assetRoleWhichProvidesPermissions Role, project, asset string) error

	AllowRole(role Role, object Object, action []Action) error
	IsAllowed(subject string, object Object, action Action) (bool, error)

	IsAllowedInProject(project *models.Project, user string, object Object, action Action) (bool, error)
	IsAllowedInAsset(asset *models.Asset, user string, object Object, action Action) (bool, error)

	AllowRoleInProject(project string, role Role, object Object, action []Action) error
	AllowRoleInAsset(asset string, role Role, object Object, action []Action) error

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
