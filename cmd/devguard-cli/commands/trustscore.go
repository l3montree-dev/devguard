package commands

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/l3montree-dev/devguard/database/models"
)

type CrowdResult struct {
	ConfidenceScore float64
	Rule            string
}

func NewTrustScoreCommand() *cobra.Command {
	trustscore := &cobra.Command{
		Use:   "trustscore",
		Short: "Assign a trust score to entities such as organizations or projects.",
		Long: "Assign a trust score to entities such as organizations or projects. " +
			"This score can influence recommendations for vulnerability assessments and risk evaluations within the system.",
		Args: cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			entityType, err := cmd.Flags().GetString("type")
			if err != nil {
				fmt.Println("Error reading type:", err)
				return err
			}

			entityID, err := cmd.Flags().GetString("entityId")
			if err != nil {
				fmt.Println("Error reading entityId:", err)
				return err
			}

			score, err := cmd.Flags().GetFloat64("score")
			if err != nil {
				fmt.Println("Error reading score:", err)
				return err
			}

			shared.LoadConfig() // nolint

			return assignTrustScore(cmd.Context(), entityType, entityID, score)
		},
	}
	trustscore.Flags().StringP("type", "t", "organization", "Type of ID that is passed. Can be 'organization' or 'project'")
	trustscore.Flags().StringP("entityId", "e", "", "ID of the entity (organization or project) to assign the trust score to")
	trustscore.Flags().Float64P("score", "s", 0, "Trust score to assign (e.g., 0.0 to 1.0)")
	err := trustscore.MarkFlagRequired("entityId")
	if err != nil {
		return nil
	}

	return trustscore
}

// ValidateTrustScore ensures the trust score is within valid range
func validateTrustScore(score float64) error {
	if score < 0 || score > 1 {
		return fmt.Errorf("trust score must be between 0.0 and 1.0, got %f", score)
	}
	return nil
}

func assignTrustScore(ctx context.Context, entityType string, entityID string, score float64) error {
	if err := validateTrustScore(score); err != nil {
		slog.Error("invalid trust score", "error", err)
		return err
	}

	entityUUID, err := uuid.Parse(entityID)
	if err != nil {
		slog.Error("invalid entity ID format", "entityID", entityID, "error", err)
		return fmt.Errorf("invalid entity ID format: %w", err)
	}

	if entityType != "organization" && entityType != "project" {
		slog.Error("invalid entity type", "type", entityType)
		return fmt.Errorf("invalid entity type: %s. Must be 'organization' or 'project'", entityType)
	}

	var assignErr error

	app := fx.New(
		fx.NopLogger,
		fx.Supply(database.GetPoolConfigFromEnv()),
		database.Module,
		repositories.Module,
		fx.Invoke(func(
			trustedEntityRepo shared.TrustedEntityRepository,
			orgRepo shared.OrganizationRepository,
			projectRepo shared.ProjectRepository,
		) error {
			tx := trustedEntityRepo.GetDB(ctx, nil).Begin()
			defer func() {
				if r := recover(); r != nil {
					tx.Rollback()
				}
			}()
			switch entityType {
			case "organization":
				_, err := orgRepo.Read(ctx, tx, entityUUID)
				if err != nil {
					slog.Error("organization not found", "organizationID", entityUUID, "error", err)
					tx.Rollback()
					return fmt.Errorf("organization with ID %s not found: %w", entityUUID, err)
				}

				err = trustedEntityRepo.UpsertOrganizationTrust(ctx, tx, entityUUID, score)
				if err != nil {
					slog.Error("failed to assign trust score to organization", "organizationID", entityUUID, "error", err)
					tx.Rollback()
					return fmt.Errorf("failed to assign trust score: %w", err)
				}

				slog.Info("successfully assigned trust score to organization",
					"organizationID", entityUUID,
					"trustScore", score)
				fmt.Printf("Successfully assigned trust score %.2f to organization %s\n", score, entityUUID)

			case "project":
				_, err := projectRepo.Read(ctx, tx, entityUUID)
				if err != nil {
					slog.Error("project not found", "projectID", entityUUID, "error", err)
					tx.Rollback()
					return fmt.Errorf("project with ID %s not found: %w", entityUUID, err)
				}

				err = trustedEntityRepo.UpsertProjectTrust(ctx, tx, entityUUID, score)
				if err != nil {
					slog.Error("failed to assign trust score to project", "projectID", entityUUID, "error", err)
					tx.Rollback()
					return fmt.Errorf("failed to assign trust score: %w", err)
				}

				slog.Info("successfully assigned trust score to project",
					"projectID", entityUUID,
					"trustScore", score)
				fmt.Printf("Successfully assigned trust score %.2f to project %s\n", score, entityUUID)
			}
			return tx.Commit().Error
		}),
	)

	if err := app.Start(context.Background()); err != nil {
		assignErr = err
	}

	if err := app.Stop(context.Background()); err != nil {
		if assignErr == nil {
			assignErr = err
		}
	}

	return assignErr
}

func CalculateConfidenceScoreForPath(ctx context.Context, rules []models.VEXRule, markedAsAffected []models.VEXRule, trustedEntities []models.TrustedEntity) ([]CrowdResult, error) {
	var result []CrowdResult
	var confidenceValues = make(map[string]float64)
	var assignErr error
	app := fx.New(
		fx.NopLogger,
		fx.Supply(database.GetPoolConfigFromEnv()),
		database.Module,
		repositories.Module,
		fx.Invoke(func(
			orgRepo shared.OrganizationRepository,
			projectRepo shared.ProjectRepository,
			assetRepo shared.AssetRepository,
		) error {

			for _, rule := range rules {
				rulaPath := strings.Join(rule.PathPattern, "->")

				asset, err := assetRepo.Read(ctx, nil, rule.AssetID)
				if err != nil {
					slog.Error("failed to read asset for VEX rule", "assetID", rule.AssetID, "error", err)
					continue
				}
				project, err := projectRepo.Read(ctx, nil, asset.ProjectID)
				if err != nil {
					slog.Error("failed to read project for asset", "projectID", asset.ProjectID, "error", err)
					continue
				}
				org, err := orgRepo.Read(ctx, nil, project.OrganizationID)
				if err != nil {
					slog.Error("failed to read organization for project", "organizationID", project.OrganizationID, "error", err)
					continue
				}
				organizationTrustscore := 0.0
				projectTrustscore := 0.0

				for _, te := range trustedEntities {
					if te.OrganizationID != nil && *te.OrganizationID == org.ID {
						organizationTrustscore = te.TrustScore
					} else if te.ProjectID != nil && *te.ProjectID == project.ID {
						projectTrustscore = te.TrustScore
					}
				}

				ruleConfidence := 1.0 * math.Max(projectTrustscore, organizationTrustscore)
				confidenceValues[rulaPath] += ruleConfidence
			}

			for _, rule := range markedAsAffected {
				rulaPath := strings.Join(rule.PathPattern, "")

				asset, err := assetRepo.Read(ctx, nil, rule.AssetID)
				if err != nil {
					slog.Error("failed to read asset for VEX rule", "assetID", rule.AssetID, "error", err)
					continue
				}
				project, err := projectRepo.Read(ctx, nil, asset.ProjectID)
				if err != nil {
					slog.Error("failed to read project for asset", "projectID", asset.ProjectID, "error", err)
					continue
				}
				org, err := orgRepo.Read(ctx, nil, project.OrganizationID)
				if err != nil {
					slog.Error("failed to read organization for project", "organizationID", project.OrganizationID, "error", err)
					continue
				}
				organizationTrustscore := 0.0
				projectTrustscore := 0.0

				for _, te := range trustedEntities {
					if te.OrganizationID != nil && *te.OrganizationID == org.ID {
						organizationTrustscore = te.TrustScore
					} else if te.ProjectID != nil && *te.ProjectID == project.ID {
						projectTrustscore = te.TrustScore
					}
				}

				ruleConfidence := 1.0 * math.Max(projectTrustscore, organizationTrustscore)
				confidenceValues[rulaPath] += ruleConfidence
			}

			totalConfidence := 0.0
			for _, conf := range confidenceValues {
				totalConfidence += conf
			}
			if totalConfidence == 0 {
				return nil
			}
			for key, value := range confidenceValues {
				result = append(result, CrowdResult{
					ConfidenceScore: value / totalConfidence,
					Rule:            key,
				})
			}
			return nil
		}),
	)

	if err := app.Start(context.Background()); err != nil {
		assignErr = err
	}

	if err := app.Stop(context.Background()); err != nil {
		assignErr = err
	}

	return result, assignErr
}
