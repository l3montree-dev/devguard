package daemons

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/monitoring"
)

func (runner *DaemonRunner) CheckArtifactCompliance(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("check artifact compliance panic")
		}()

		for assetWithDetails := range input {
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.check-artifact-compliance")

			for _, assetVersion := range assetWithDetails.assetVersions {
				for _, artifact := range assetVersion.Artifacts {
					sarifDoc, err := runner.complianceService.ArtifactCompliance(stageCtx, assetWithDetails.project.ID, assetVersion, artifact)
					if err != nil {
						slog.Error("could not evaluate artifact compliance",
							"assetID", assetWithDetails.asset.ID,
							"assetVersion", assetVersion.Name,
							"artifactName", artifact.ArtifactName,
							"err", err,
						)
						continue
					}
					if err := runner.complianceRiskService.HandleArtifactCompliance(stageCtx, nil, "system", nil, assetVersion, artifact, sarifDoc); err != nil {
						slog.Error("could not handle artifact compliance risks",
							"assetID", assetWithDetails.asset.ID,
							"assetVersion", assetVersion.Name,
							"artifactName", artifact.ArtifactName,
							"err", err,
						)
					}
				}
			}

			span.End()
			out <- assetWithDetails
		}
	}()

	return out
}

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
					if err := runner.attestationService.GenerateAndStoreDevguardAttestation(stageCtx, assetVersion.AssetID, assetVersion.Name, artifact.ArtifactName); err != nil {
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
