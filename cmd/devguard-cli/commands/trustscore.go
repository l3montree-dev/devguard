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

			return assignTrustScore(entityType, entityID, score)
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

func assignTrustScore(inType string, inEntityID string, inScore float64) error {
	// Validate trust score
	if err := repositories.ValidateTrustScore(inScore); err != nil {
		slog.Error("invalid trust score", "error", err)
		return err
	}

	// Parse UUID
	entityUUID, err := uuid.Parse(inEntityID)
	if err != nil {
		slog.Error("invalid entity ID format", "entityID", inEntityID, "error", err)
		return fmt.Errorf("invalid entity ID format: %w", err)
	}

	// Validate entity type
	if inType != "organization" && inType != "project" {
		slog.Error("invalid entity type", "type", inType)
		return fmt.Errorf("invalid entity type: %s. Must be 'organization' or 'project'", inType)
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
			ctx := context.Background()
			_ = ctx

			// Verify entity exists before assigning trust score
			if inType == "organization" {
				_, err := orgRepo.Read(entityUUID)
				if err != nil {
					slog.Error("organization not found", "organizationID", entityUUID, "error", err)
					return fmt.Errorf("organization with ID %s not found: %w", entityUUID, err)
				}

				// Upsert trust score
				err = trustedEntityRepo.UpsertOrganizationTrust(nil, entityUUID, inScore)
				if err != nil {
					slog.Error("failed to assign trust score to organization", "organizationID", entityUUID, "error", err)
					return fmt.Errorf("failed to assign trust score: %w", err)
				}

				slog.Info("successfully assigned trust score to organization",
					"organizationID", entityUUID,
					"trustScore", inScore)
				fmt.Printf("Successfully assigned trust score %.2f to organization %s\n", inScore, entityUUID)

			} else if inType == "project" {
				_, err := projectRepo.Read(entityUUID)
				if err != nil {
					slog.Error("project not found", "projectID", entityUUID, "error", err)
					return fmt.Errorf("project with ID %s not found: %w", entityUUID, err)
				}

				// Upsert trust score
				err = trustedEntityRepo.UpsertProjectTrust(nil, entityUUID, inScore)
				if err != nil {
					slog.Error("failed to assign trust score to project", "projectID", entityUUID, "error", err)
					return fmt.Errorf("failed to assign trust score: %w", err)
				}

				slog.Info("successfully assigned trust score to project",
					"projectID", entityUUID,
					"trustScore", inScore)
				fmt.Printf("Successfully assigned trust score %.2f to project %s\n", inScore, entityUUID)
			}

			return nil
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

func CalculateConfidenceScoreForPath(inRules []models.VEXRule, inMarkedAsAffected []models.VEXRule, inTrustedEntities []models.TrustedEntity) ([]CrowdResult, error) {
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

			for _, rule := range inRules {
				//Are the rule paths using unique Ids?
				rulaPath := strings.Join(rule.PathPattern, "")

				asset, err := assetRepo.Read(rule.AssetID)
				if err != nil {
					slog.Error("failed to read asset for VEX rule", "assetID", rule.AssetID, "error", err)
					continue
				}
				project, err := projectRepo.Read(asset.ProjectID)
				if err != nil {
					slog.Error("failed to read project for asset", "projectID", asset.ProjectID, "error", err)
					continue
				}
				org, err := orgRepo.Read(project.OrganizationID)
				if err != nil {
					slog.Error("failed to read organization for project", "organizationID", project.OrganizationID, "error", err)
					continue
				}
				organizationTrustscore := 0.0
				projectTrustscore := 0.0

				for _, te := range inTrustedEntities {
					if *te.OrganizationID == org.ID {
						organizationTrustscore = te.Trustscore
					} else if *te.ProjectID == project.ID {
						projectTrustscore = te.Trustscore
					}
				}

				ruleConfidence := 1.0 * math.Max(projectTrustscore, organizationTrustscore)
				confidenceValues[rulaPath] += ruleConfidence
			}

			for _, rule := range inMarkedAsAffected {
				rulaPath := strings.Join(rule.PathPattern, "")

				asset, err := assetRepo.Read(rule.AssetID)
				if err != nil {
					slog.Error("failed to read asset for VEX rule", "assetID", rule.AssetID, "error", err)
					continue
				}
				project, err := projectRepo.Read(asset.ProjectID)
				if err != nil {
					slog.Error("failed to read project for asset", "projectID", asset.ProjectID, "error", err)
					continue
				}
				org, err := orgRepo.Read(project.OrganizationID)
				if err != nil {
					slog.Error("failed to read organization for project", "organizationID", project.OrganizationID, "error", err)
					continue
				}
				organizationTrustscore := 0.0
				projectTrustscore := 0.0

				for _, te := range inTrustedEntities {
					if *te.OrganizationID == org.ID {
						organizationTrustscore = te.Trustscore
					} else if *te.ProjectID == project.ID {
						projectTrustscore = te.Trustscore
					}
				}

				ruleConfidence := 1.0 * math.Max(projectTrustscore, organizationTrustscore)
				confidenceValues[rulaPath] += ruleConfidence
			}

			//Calculate sum of all paths and percentages
			totalConfidence := 0.0
			for _, conf := range confidenceValues {
				totalConfidence += conf
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
