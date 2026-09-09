package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type logService struct {
	logRepository          shared.LogRepository
	organizationRepository shared.OrganizationRepository
	projectRepository      shared.ProjectRepository
	assetRepository        shared.AssetRepository
	assetVersionRepository shared.AssetVersionRepository
}

func NewLogsService(
	logRepository shared.LogRepository,
	organizationRepository shared.OrganizationRepository,
	projectRepository shared.ProjectRepository,
	assetRepository shared.AssetRepository,
	assetVersionRepository shared.AssetVersionRepository,
) *logService {
	return &logService{
		logRepository:          logRepository,
		organizationRepository: organizationRepository,
		projectRepository:      projectRepository,
		assetRepository:        assetRepository,
		assetVersionRepository: assetVersionRepository,
	}
}

func (s logService) cascadeIDs(ctx context.Context, tx *gorm.DB, orgID, projectID, assetID uuid.UUID, assetVersionName string) (uuid.UUID, uuid.UUID, uuid.UUID, string, error) {
	var cascadedProjectID, cascadedAssetID uuid.UUID
	var cascadedAssetVersionName string

	if assetID != uuid.Nil {
		asset, err := s.assetRepository.Read(ctx, tx, assetID)
		if err != nil {
			return uuid.Nil, uuid.Nil, uuid.Nil, "", err
		}
		projectID = asset.ProjectID

		if assetVersionName != "" {
			assetVersion, err := s.assetVersionRepository.Read(ctx, tx, assetVersionName, assetID)
			if err != nil {
				return uuid.Nil, uuid.Nil, uuid.Nil, "", err
			}
			cascadedAssetVersionName = assetVersion.Name
		}
		cascadedAssetID = assetID
	}
	// If asset is nil, continue with project level -> Error was on project level instead of asset level
	if projectID != uuid.Nil {
		cascadedProjectID = projectID
		project, err := s.projectRepository.Read(ctx, tx, projectID)
		if err != nil {
			return uuid.Nil, uuid.Nil, uuid.Nil, "", err
		}
		orgID = project.OrganizationID
	}

	return orgID, cascadedProjectID, cascadedAssetID, cascadedAssetVersionName, nil
}

func (s logService) StoreCaptureException(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID uuid.UUID, assetID uuid.UUID, assetVersionName string, message string) error {
	cascadedOrgID, cascadedProjectID, cascadedAssetID, cascadedAssetVersionName, err := s.cascadeIDs(ctx, tx, orgID, projectID, assetID, assetVersionName)
	if err != nil {
		return err
	}

	log := models.Log{
		OrgID:            cascadedOrgID,
		ProjectID:        cascadedProjectID,
		AssetID:          cascadedAssetID,
		AssetVersionName: cascadedAssetVersionName,
		Message:          message,
		LogLevel:         logger.Error,
	}

	err = s.logRepository.Save(ctx, tx, &log)
	if err != nil {
		return err
	}

	return nil
}

func (s logService) StoreRecoverPanic(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID uuid.UUID, assetID uuid.UUID, assetVersionName string, message string) error {
	cascadedOrgID, cascadedProjectID, cascadedAssetID, cascadedAssetVersionName, err := s.cascadeIDs(ctx, tx, orgID, projectID, assetID, assetVersionName)
	if err != nil {
		return err
	}

	log := models.Log{
		OrgID:            cascadedOrgID,
		ProjectID:        cascadedProjectID,
		AssetID:          cascadedAssetID,
		AssetVersionName: cascadedAssetVersionName,
		Message:          message,
		LogLevel:         logger.Error,
	}

	err = s.logRepository.Save(ctx, tx, &log)
	if err != nil {
		return err
	}

	return nil
}

func (s logService) ListPaged(ctx shared.Context, tx *gorm.DB, orgID uuid.UUID, projectID uuid.UUID, assetID uuid.UUID) (shared.Paged[models.Log], error) {
	pageInfo := shared.GetPageInfo(ctx)

	if orgID == uuid.Nil {
		return shared.Paged[models.Log]{}, fmt.Errorf("orgID required")
	}

	logs, err := s.logRepository.ListPaged(ctx.Request().Context(), tx, orgID, projectID, assetID, pageInfo)
	if err != nil {
		return shared.Paged[models.Log]{}, err
	}

	return logs, nil
}
