// Copyright (C) 2026 l3montree GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later

package trivyoperatorint

import (
	"bytes"
	"context"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
)

var trivyOperatorKinds = map[string]bool{
	"VulnerabilityReport":         false,
	"SbomReport":                  true,
	"ConfigAuditReport":           false,
	"ClusterRbacAssessmentReport": false,
	"ExposedSecretReport":         false,
	"InfraAssessmentReport":       false,
	"ClusterComplianceReport":     false,
	"RbacAssessmentReport":        false,
}

// operatorObject is the inner object of a Trivy Operator webhook payload.
type operatorObject struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Report struct {
		Artifact struct {
			Tag string `json:"tag"`
		} `json:"artifact"`
		Components json.RawMessage `json:"components"` // CycloneDX BOM
	} `json:"report"`
}

// webhookPayload is the shape of Trivy Operator webhook requests.
type webhookPayload struct {
	Verb           string         `json:"verb"`
	OperatorObject operatorObject `json:"operatorObject"`
}

type TrivyOperatorIntegration struct {
	repository         shared.TrivyOperatorIntegrationRepository
	orgRepository      shared.OrganizationRepository
	projectRepository  shared.ProjectRepository
	assetRepository    shared.AssetRepository
	assetVersionRepo   shared.AssetVersionRepository
	artifactRepository shared.ArtifactRepository
	assetVersionSvc    shared.AssetVersionService
	assetService       shared.AssetService
	projectService     shared.ProjectService
	rbacProvider       shared.RBACProvider
	// set via SetScanService after construction to break the DI cycle:
	// TrivyOperatorIntegration → ScanService → DependencyVulnService → IntegrationAggregate → TrivyOperatorIntegration
	scanService shared.ScanService
}

var _ shared.ThirdPartyIntegration = &TrivyOperatorIntegration{}

func NewTrivyOperatorIntegration(
	repository shared.TrivyOperatorIntegrationRepository,
	orgRepository shared.OrganizationRepository,
	projectRepository shared.ProjectRepository,
	assetRepository shared.AssetRepository,
	assetVersionRepo shared.AssetVersionRepository,
	artifactRepository shared.ArtifactRepository,
	assetVersionSvc shared.AssetVersionService,
	projectService shared.ProjectService,
	rbacProvider shared.RBACProvider,
) *TrivyOperatorIntegration {
	return &TrivyOperatorIntegration{
		repository:         repository,
		orgRepository:      orgRepository,
		projectRepository:  projectRepository,
		assetRepository:    assetRepository,
		assetVersionRepo:   assetVersionRepo,
		artifactRepository: artifactRepository,
		assetVersionSvc:    assetVersionSvc,
		projectService:     projectService,
		rbacProvider:       rbacProvider,
	}
}

func (t *TrivyOperatorIntegration) SetAssetService(s shared.AssetService) {
	t.assetService = s
}

func (t *TrivyOperatorIntegration) SetScanService(s shared.ScanService) {
	t.scanService = s
}

func (t *TrivyOperatorIntegration) GetID() shared.IntegrationID {
	return shared.TrivyOperatorIntegrationID
}

// WantsToHandleWebhook detects Trivy Operator requests by the "kind" field in the JSON body.
func (t *TrivyOperatorIntegration) WantsToHandleWebhook(ctx shared.Context) bool {
	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return false
	}
	ctx.Request().Body = io.NopCloser(bytes.NewBuffer(body))

	var probe struct {
		Verb           string `json:"verb"`
		OperatorObject struct {
			Kind string `json:"kind"`
		} `json:"operatorObject"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	fmt.Println("Trivy Operator probe:", "kind", probe.OperatorObject.Kind, "verb", probe.Verb)
	if probe.Verb == "delete" {

		//return false
	}
	if trivyOperatorKinds[probe.OperatorObject.Kind] || probe.Verb == "delete" {
		fmt.Printf("Trivy Operator report received: kind=%s, remote_addr=%s, user_agent=%s, content_length=%d\n", probe.OperatorObject.Kind, ctx.RealIP(), ctx.Request().Header.Get("User-Agent"), ctx.Request().ContentLength)
	}
	return trivyOperatorKinds[probe.OperatorObject.Kind] || probe.Verb == "delete"
}

func (t *TrivyOperatorIntegration) HandleWebhook(ctx shared.Context) error {
	//reqCtx := ctx.Request().Context()
	reqCtx := context.WithoutCancel(ctx.Request().Context())
	// --- Auth ---
	secret := strings.TrimPrefix(ctx.Request().Header.Get("Authorization"), "Bearer ")
	if secret == "" {
		return ctx.JSON(401, map[string]string{"error": "missing Authorization header"})
	}
	integration, err := t.repository.FindBySecret(reqCtx, nil, secret)
	if err != nil {
		slog.Warn("trivy operator: unknown secret", "remote_addr", ctx.RealIP())
		return ctx.JSON(401, map[string]string{"error": "unauthorized"})
	}

	// --- Parse body ---
	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return err
	}

	//save the file for debugging purposes

	if err := os.WriteFile(fmt.Sprintf("trivy-operator-report-%s.json", time.Now().Format("20060102-150405")), body, 0644); err != nil {
		slog.Error("trivy operator: could not save report body", "err", err)
	}

	var payload webhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return ctx.JSON(400, map[string]string{"error": "invalid JSON"})
	}

	report := payload.OperatorObject
	containerName := report.Metadata.Labels["trivy-operator.container.name"]
	namespace := report.Metadata.Namespace
	tag := report.Report.Artifact.Tag
	if containerName == "" {
		return ctx.JSON(400, map[string]string{"error": "missing trivy-operator.container.name label"})
	}

	// --- Load org ---
	org, err := t.orgRepository.GetOrgByID(reqCtx, nil, integration.OrgID)
	if err != nil {
		slog.Error("trivy operator: org not found", "orgID", integration.OrgID, "err", err)
		return ctx.JSON(500, map[string]string{"error": "org not found"})
	}

	// --- Handle delete verb ---
	if payload.Verb == "delete" {
		return t.handleDelete(reqCtx, ctx, org.ID, integration.ClusterID, namespace, containerName, tag)
	}

	// --- Find or create cluster project (top-level) ---
	clusterProject, err := t.findOrCreateProject(reqCtx, org.ID, integration.ClusterID, integration.Name, nil, models.ProjectTypeDefault)
	if err != nil {
		return ctx.JSON(500, map[string]string{"error": "could not find or create cluster project"})
	}

	// --- Find or create namespace sub-project ---
	namespaceProject, err := t.findOrCreateProject(reqCtx, org.ID, namespace, namespace, &clusterProject.ID, models.ProjectTypeDefault)
	if err != nil {
		return ctx.JSON(500, map[string]string{"error": "could not find or create namespace project"})
	}

	// --- Find or create asset ---
	asset, err := t.findOrCreateAsset(reqCtx, org.ID, namespaceProject.ID, containerName)
	if err != nil {
		return ctx.JSON(500, map[string]string{"error": "could not find or create asset"})
	}

	// --- Parse CycloneDX BOM from report.components ---
	bom := new(cdx.BOM)
	if err := json.Unmarshal(report.Report.Components, bom); err != nil {
		slog.Error("trivy operator: failed to parse CycloneDX BOM", "err", err)
		return ctx.JSON(400, map[string]string{"error": "invalid CycloneDX BOM in report.components"})
	}

	// --- Scan ---
	assetVersionName := tag
	if assetVersionName == "" {
		assetVersionName = "latest"
	}
	artifactName := normalize.ArtifactPurl("trivy-operator", fmt.Sprintf("%s/%s/%s", org.Slug, clusterProject.Slug, asset.Slug))

	normalized, err := normalize.SBOMGraphFromCycloneDX(bom, artifactName, "trivy-operator", asset.KeepOriginalSbomRootComponent)
	if err != nil {
		slog.Error("trivy operator: failed to normalize BOM", "err", err)
		return ctx.JSON(400, map[string]string{"error": "could not normalize SBOM"})
	}

	assetVersion, err := t.assetVersionRepo.FindOrCreate(reqCtx, nil, assetVersionName, asset.ID, tag != "", nil)
	if err != nil {
		slog.Error("trivy operator: could not find or create asset version", "err", err)
		return ctx.JSON(500, map[string]string{"error": "could not find or create asset version"})
	}

	artifact := models.Artifact{
		ArtifactName:     artifactName,
		AssetVersionName: assetVersion.Name,
		AssetID:          asset.ID,
	}
	if err := t.artifactRepository.Save(reqCtx, nil, &artifact); err != nil {
		slog.Error("trivy operator: could not save artifact", "err", err)
		return ctx.JSON(500, map[string]string{"error": "could not save artifact"})
	}

	tx := t.assetVersionRepo.GetDB(reqCtx, nil).Begin()
	defer tx.Rollback() //nolint:errcheck

	wholeSBOM, err := t.assetVersionSvc.UpdateSBOM(reqCtx, tx, org, *clusterProject, *asset, assetVersion, artifactName, normalized)
	if err != nil {
		slog.Error("trivy operator: could not update SBOM", "err", err)
		return ctx.JSON(500, map[string]string{"error": "could not update SBOM"})
	}

	userAgent := "trivy-operator"
	_, _, _, err = t.scanService.ScanNormalizedSBOM(reqCtx, tx, org, *clusterProject, *asset, assetVersion, artifact, wholeSBOM, "trivy-operator", &userAgent)
	if err != nil {
		slog.Error("trivy operator: scan failed", "err", err)
		return ctx.JSON(500, map[string]string{"error": "scan failed"})
	}

	if err := tx.Commit().Error; err != nil {
		slog.Error("trivy operator: could not commit transaction", "err", err)
		return ctx.JSON(500, map[string]string{"error": "could not commit"})
	}

	slog.Info("trivy operator: SBOM scanned and saved",
		"org", org.Slug,
		"cluster", clusterProject.Slug,
		"namespace", namespaceProject.Slug,
		"asset", asset.Slug,
		"assetVersion", assetVersion.Name,
	)

	return ctx.JSON(202, map[string]string{"status": "accepted"})
}

func (t *TrivyOperatorIntegration) handleDelete(ctx context.Context, httpCtx shared.Context, orgID uuid.UUID, clusterID, namespace, containerName, tag string) error {
	clusterProject, err := t.projectRepository.ReadBySlug(ctx, nil, orgID, clusterID)
	if err != nil {
		slog.Warn("trivy operator: delete - cluster project not found", "clusterID", clusterID)
		return httpCtx.JSON(404, map[string]string{"error": "cluster project not found"})
	}

	namespaceProject, err := t.projectRepository.ReadBySlug(ctx, nil, orgID, namespace)
	if err != nil {
		slog.Warn("trivy operator: delete - namespace project not found", "namespace", namespace)
		return httpCtx.JSON(404, map[string]string{"error": "namespace project not found"})
	}
	_ = clusterProject

	slug := strings.ToLower(strings.ReplaceAll(containerName, "/", "-"))
	asset, err := t.assetRepository.ReadBySlug(ctx, nil, namespaceProject.ID, slug)
	if err != nil {
		slog.Warn("trivy operator: delete - asset not found", "containerName", containerName)
		return httpCtx.JSON(404, map[string]string{"error": "asset not found"})
	}

	assetVersionName := tag
	if assetVersionName == "" {
		assetVersionName = "latest"
	}

	assetVersion, err := t.assetVersionRepo.Read(ctx, nil, assetVersionName, asset.ID)
	if err != nil {
		slog.Warn("trivy operator: delete - asset version not found", "assetVersionName", assetVersionName, "assetID", asset.ID)
		return httpCtx.JSON(404, map[string]string{"error": "asset version not found"})
	}

	if err := t.assetVersionRepo.Delete(ctx, nil, &assetVersion); err != nil {
		slog.Error("trivy operator: delete - could not delete asset version", "err", err)
		return httpCtx.JSON(500, map[string]string{"error": "could not delete asset version"})
	}

	slog.Info("trivy operator: asset version deleted",
		"asset", asset.Slug,
		"assetVersion", assetVersion.Name,
	)
	return httpCtx.JSON(200, map[string]string{"status": "deleted"})
}

func (t *TrivyOperatorIntegration) findOrCreateProject(ctx context.Context, orgID uuid.UUID, slug, name string, parentID *uuid.UUID, projectType models.ProjectType) (*models.Project, error) {
	project, err := t.projectRepository.ReadBySlug(ctx, nil, orgID, slug)
	if err == nil {
		return &project, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	newProject := &models.Project{
		Name:           name,
		Slug:           slug,
		OrganizationID: orgID,
		ParentID:       parentID,
		Type:           projectType,
	}
	if err := t.projectRepository.Create(ctx, nil, newProject); err != nil {
		return nil, err
	}
	domainRBAC := t.rbacProvider.GetDomainRBAC(orgID.String())
	if err := t.projectService.BootstrapProject(ctx, domainRBAC, newProject); err != nil {
		slog.Error("trivy operator: could not bootstrap project RBAC", "err", err)
	}
	return newProject, nil
}

func (t *TrivyOperatorIntegration) findOrCreateAsset(ctx context.Context, orgID uuid.UUID, projectID uuid.UUID, name string) (*models.Asset, error) {
	slug := strings.ToLower(strings.ReplaceAll(name, "/", "-"))

	asset, err := t.assetRepository.ReadBySlug(ctx, nil, projectID, slug)
	if err == nil {
		return &asset, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	newAsset := &models.Asset{
		Name:      name,
		Slug:      slug,
		ProjectID: projectID,
	}
	if err := t.assetRepository.Create(ctx, nil, newAsset); err != nil {
		return nil, err
	}

	domainRBAC := t.rbacProvider.GetDomainRBAC(orgID.String())
	if err := t.assetService.BootstrapAsset(ctx, domainRBAC, newAsset); err != nil {
		slog.Error("trivy operator: could not bootstrap asset RBAC", "err", err)
	}

	return newAsset, nil
}

func (t *TrivyOperatorIntegration) Create(ctx shared.Context) error {
	var data struct {
		Name      string `json:"name"`
		ClusterID string `json:"clusterId"`
	}
	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}
	if data.Name == "" || data.ClusterID == "" {
		return ctx.JSON(400, "name and clusterId are required")
	}

	secretBytes := make([]byte, 32)
	if _, err := cryptoRand.Read(secretBytes); err != nil {
		return ctx.JSON(500, "could not generate secret")
	}
	secret := hex.EncodeToString(secretBytes)

	integration := &models.TrivyOperatorIntegration{
		Name:      data.Name,
		ClusterID: data.ClusterID,
		Secret:    secret,
		OrgID:     shared.GetOrg(ctx).GetID(),
	}
	if err := t.repository.Save(ctx.Request().Context(), nil, integration); err != nil {
		slog.Error("trivy operator: could not save integration", "err", err)
		return ctx.JSON(500, "could not save integration")
	}

	return ctx.JSON(200, dtos.TrivyOperatorIntegrationDTO{
		ID:        integration.ID.String(),
		Name:      integration.Name,
		ClusterID: integration.ClusterID,
		Secret:    integration.Secret,
	})
}

func (t *TrivyOperatorIntegration) Delete(ctx shared.Context) error {
	id := ctx.Param("trivy_operator_integration_id")
	parsedID, err := uuid.Parse(id)
	if err != nil {
		return ctx.JSON(400, "invalid id")
	}
	if err := t.repository.Delete(ctx.Request().Context(), nil, parsedID); err != nil {
		slog.Error("trivy operator: could not delete integration", "err", err)
		return ctx.JSON(500, "could not delete integration")
	}
	return ctx.JSON(200, map[string]string{"message": "deleted"})
}

// --- Stubs for interface compliance ---

func (t *TrivyOperatorIntegration) ListOrgs(_ shared.Context) ([]models.Org, error) {
	return nil, nil
}

func (t *TrivyOperatorIntegration) ListGroups(_ context.Context, _ string, _ string) ([]models.Project, []shared.Role, error) {
	return nil, nil, nil
}

func (t *TrivyOperatorIntegration) ListProjects(_ context.Context, _ string, _ string, _ string) ([]models.Asset, []shared.Role, error) {
	return nil, nil, nil
}

func (t *TrivyOperatorIntegration) ListRepositories(_ shared.Context) ([]dtos.GitRepository, error) {
	return nil, nil
}

func (t *TrivyOperatorIntegration) HasAccessToExternalEntityProvider(_ shared.Context, _ string) (bool, error) {
	return false, nil
}

func (t *TrivyOperatorIntegration) HandleEvent(_ context.Context, _ any, _ *string) error {
	return nil
}

func (t *TrivyOperatorIntegration) CreateIssue(_ context.Context, _ models.Asset, _ string, _ models.Vuln, _ string, _ string, _ string, _ string, _ *string) error {
	return nil
}

func (t *TrivyOperatorIntegration) UpdateIssue(_ context.Context, _ models.Asset, _ string, _ models.Vuln, _ *string) error {
	return nil
}

func (t *TrivyOperatorIntegration) CreateLabels(_ context.Context, _ models.Asset) error {
	return nil
}

func (t *TrivyOperatorIntegration) CompareIssueStatesAndResolveDifferences(_ context.Context, _ models.Asset, _ []models.DependencyVuln) error {
	return nil
}
