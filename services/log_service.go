package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
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

func (s logService) cascadeIDs(ctx context.Context, tx *gorm.DB, orgID, projectID, assetID *uuid.UUID) (*uuid.UUID, *uuid.UUID, *uuid.UUID, error) {
	//Given any ID, this function is suppose to find every ID of every parent if not existing

	var cascadedProjectID, cascadedAssetID *uuid.UUID

	if assetID != nil {
		asset, err := s.assetRepository.ReadWithoutErrorLog(ctx, tx, *assetID)
		if err != nil {
			return nil, nil, nil, err
		}
		projectID = &asset.ProjectID

		cascadedAssetID = assetID
	}
	// If asset is nil, continue with project level -> Error was on project level instead of asset level
	if projectID != nil {
		cascadedProjectID = projectID
		project, err := s.projectRepository.ReadWithoutErrorLog(ctx, tx, *projectID)
		if err != nil {
			return nil, nil, nil, err
		}
		orgID = &project.OrganizationID
	}

	return orgID, cascadedProjectID, cascadedAssetID, nil
}

func (s logService) SaveLog(ctx context.Context, tx *gorm.DB, orgID, projectID, assetID *uuid.UUID, message string) error {
	cascadedOrgID, cascadedProjectID, cascadedAssetID, err := s.cascadeIDs(ctx, tx, orgID, projectID, assetID)
	if err != nil {
		return err
	}

	log := models.Log{
		OrgID:     cascadedOrgID,
		ProjectID: cascadedProjectID,
		AssetID:   cascadedAssetID,
		Message:   message,
		LogLevel:  dtos.LogLevelError,
	}

	err = s.logRepository.Save(ctx, tx, &log)
	if err != nil {
		return err
	}

	return nil
}

func (s logService) ListPaged(ctx shared.Context, tx *gorm.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, pageInfo shared.PageInfo) (shared.Paged[dtos.LogDTO], error) {

	if orgID == uuid.Nil {
		return shared.Paged[dtos.LogDTO]{}, fmt.Errorf("orgID required")
	}

	logs, err := s.logRepository.ListPaged(ctx.Request().Context(), tx, orgID, projectID, assetID, pageInfo)
	if err != nil {
		return shared.Paged[dtos.LogDTO]{}, err
	}

	return logs, nil
}
