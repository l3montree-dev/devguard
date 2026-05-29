package daemons

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/monitoring"
)

const secondsPerHour = 3600.0

// GenerateDevguardAttestations is a pipeline stage that computes the DevGuard asset
// metrics attestation for every asset version and upserts it into the attestations table.
// It runs after CollectStats so that risk data is already up to date.
func (runner *DaemonRunner) GenerateDevguardAttestations(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("generate devguard attestations panic")
		}()

		for assetWithDetails := range input {
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.generate-devguard-attestations")

			for _, assetVersion := range assetWithDetails.assetVersions {
				for _, artifact := range assetVersion.Artifacts {
					if err := runner.GenerateAndStoreDevguardAttestation(stageCtx, assetVersion.AssetID, assetVersion.Name, artifact.ArtifactName); err != nil {
						slog.Error("could not generate devguard attestation",
							"assetID", assetWithDetails.asset.ID,
							"assetVersion", assetVersion.Name,
							"artifactName", artifact.ArtifactName,
							"err", err,
						)
						// non-fatal: log and continue to next artifact
					}
				}
			}

			span.End()
			out <- assetWithDetails
		}
	}()

	return out
}

func (runner *DaemonRunner) GenerateAndStoreDevguardAttestation(ctx context.Context, assetID uuid.UUID, assetVersionName string, artifactName string) error {
	averages, err := runner.statisticsRepository.AverageFixingTimes(ctx, nil, assetVersionName, assetID)
	if err != nil {
		return err
	}

	attestationDTO := dtos.DevguardAssetAttestationDTO{
		Type:          dtos.DevguardAssetAttestationPredicateType,
		GeneratedAt:   time.Now().UTC(),
		SchemaVersion: "1.0.0",
		MeanTimeToRemediate: dtos.MeanTimeToRemediateDTO{
			RiskLowAvgHours:      averages.RiskAvgLow / secondsPerHour,
			RiskMediumAvgHours:   averages.RiskAvgMedium / secondsPerHour,
			RiskHighAvgHours:     averages.RiskAvgHigh / secondsPerHour,
			RiskCriticalAvgHours: averages.RiskAvgCritical / secondsPerHour,
			CVSSLowAvgHours:      averages.CVSSAvgLow / secondsPerHour,
			CVSSMediumAvgHours:   averages.CVSSAvgMedium / secondsPerHour,
			CVSSHighAvgHours:     averages.CVSSAvgHigh / secondsPerHour,
			CVSSCriticalAvgHours: averages.CVSSAvgCritical / secondsPerHour,
		},
	}

	content, err := json.Marshal(attestationDTO)
	if err != nil {
		return err
	}

	var contentMap map[string]any
	if err := json.Unmarshal(content, &contentMap); err != nil {
		return err
	}

	attestation := models.Attestation{
		AssetID:          assetID,
		AssetVersionName: assetVersionName,
		ArtifactName:     artifactName,
		PredicateType:    dtos.DevguardAssetAttestationPredicateType,
		Content:          contentMap,
	}

	return runner.attestationRepository.Create(ctx, nil, &attestation)
}
