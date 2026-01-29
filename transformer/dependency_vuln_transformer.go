// Copyright (C) 2025 l3montree GmbH
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

package transformer

import (
	"net/url"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
)

func CVEToDTO(cve models.CVE) dtos.CVEDTO {
	return dtos.CVEDTO{
		CVE:                   cve.CVE,
		CreatedAt:             cve.CreatedAt,
		UpdatedAt:             cve.UpdatedAt,
		DatePublished:         cve.DatePublished,
		DateLastModified:      cve.DateLastModified,
		Description:           cve.Description,
		CVSS:                  cve.CVSS,
		References:            cve.References,
		CISAExploitAdd:        cve.CISAExploitAdd,
		CISAActionDue:         cve.CISAActionDue,
		CISARequiredAction:    cve.CISARequiredAction,
		CISAVulnerabilityName: cve.CISAVulnerabilityName,
		EPSS:                  cve.EPSS,
		Percentile:            cve.Percentile,
		Vector:                cve.Vector,
		Risk:                  cve.Risk,
		Exploits:              utils.Map(cve.Exploits, ExploitModelToDTO),
		Relationships:         utils.Map(cve.Relationships, RelationshipToDTO),
	}
}

func RelationshipToDTO(relation models.CVERelationship) dtos.RelationshipDTO {
	return dtos.RelationshipDTO{
		RelationshipType: relation.RelationshipType,
		TargetCVE:        relation.TargetCVE,
	}
}
func DependencyVulnToDTO(f models.DependencyVuln) dtos.DependencyVulnDTO {
	return dtos.DependencyVulnDTO{
		ID:                    f.ID,
		Message:               f.Message,
		AssetVersionName:      f.AssetVersionName,
		AssetID:               f.AssetID.String(),
		State:                 dtos.VulnState(f.State),
		CVE:                   CVEToDTO(f.CVE),
		CVEID:                 f.CVEID,
		ComponentPurl:         f.ComponentPurl,
		ComponentFixedVersion: f.ComponentFixedVersion,
		VulnerabilityPath:     f.VulnerabilityPath,
		Effort:                f.Effort,
		RiskAssessment:        f.RiskAssessment,
		RawRiskAssessment:     f.RawRiskAssessment,
		Priority:              f.Priority,
		LastDetected:          f.LastDetected,
		CreatedAt:             f.CreatedAt,
		TicketID:              f.TicketID,
		TicketURL:             f.TicketURL,
		ManualTicketCreation:  f.ManualTicketCreation,
		RiskRecalculatedAt:    f.RiskRecalculatedAt,
		Artifacts:             utils.Map(f.Artifacts, ArtifactModelToDTO),
	}
}

func DependencyVulnToDetailedDTO(dependencyVuln models.DependencyVuln) dtos.DetailedDependencyVulnDTO {
	return dtos.DetailedDependencyVulnDTO{
		DependencyVulnDTO: dtos.DependencyVulnDTO{
			ID:                    dependencyVuln.ID,
			Message:               dependencyVuln.Message,
			AssetVersionName:      dependencyVuln.AssetVersionName,
			AssetID:               dependencyVuln.AssetID.String(),
			State:                 dependencyVuln.State,
			CVE:                   CVEToDTO(dependencyVuln.CVE),
			CVEID:                 dependencyVuln.CVEID,
			ComponentPurl:         dependencyVuln.ComponentPurl,
			ComponentFixedVersion: dependencyVuln.ComponentFixedVersion,
			VulnerabilityPath:     dependencyVuln.VulnerabilityPath,
			Effort:                dependencyVuln.Effort,
			RiskAssessment:        dependencyVuln.RiskAssessment,
			RawRiskAssessment:     dependencyVuln.RawRiskAssessment,
			Priority:              dependencyVuln.Priority,
			LastDetected:          dependencyVuln.LastDetected,
			CreatedAt:             dependencyVuln.CreatedAt,
			Artifacts:             utils.Map(dependencyVuln.Artifacts, ArtifactModelToDTO),
			TicketID:              dependencyVuln.TicketID,
			TicketURL:             dependencyVuln.TicketURL,
			ManualTicketCreation:  dependencyVuln.ManualTicketCreation,
			RiskRecalculatedAt:    dependencyVuln.RiskRecalculatedAt,
		},
		Events: utils.Map(dependencyVuln.Events, func(ev models.VulnEvent) dtos.VulnEventDTO {
			return dtos.VulnEventDTO{
				ID:                      ev.ID,
				Type:                    ev.Type,
				VulnID:                  ev.VulnID,
				UserID:                  ev.UserID,
				Justification:           ev.Justification,
				MechanicalJustification: ev.MechanicalJustification,
				AssetVersionName:        GetAssetVersionName(dependencyVuln.Vulnerability, ev),
				ArbitraryJSONData:       ev.GetArbitraryJSONData(),
				CreatedAt:               ev.CreatedAt,
				Upstream:                ev.Upstream,
			}
		}),
	}
}

func GetAssetVersionName(vuln models.Vulnerability, ev models.VulnEvent) string {
	if ev.OriginalAssetVersionName != nil {
		return *ev.OriginalAssetVersionName
	}
	return vuln.AssetVersionName // fallback to the vuln's asset version name if event does not have it
}

// VulnInPackageToDependencyVulns converts a vulnerability to multiple DependencyVuln objects,
// one for each unique path through the dependency graph. This ensures that the same CVE
// appearing through different dependency paths (e.g., A -> trivy -> stdlib vs A -> cosign -> stdlib)
// creates separate vulnerability records.
func VulnInPackageToDependencyVulns(vuln models.VulnInPackage, sbom *normalize.SBOMGraph, assetID uuid.UUID, assetVersionName string, artifactName string) []models.DependencyVuln {
	vulns := VulnInPackageToDependencyVulnsWithoutArtifact(vuln, sbom, assetID, assetVersionName)

	// set the artifact for each vuln
	for i := range vulns {
		vulns[i].Artifacts = []models.Artifact{
			{
				ArtifactName:     artifactName,
				AssetVersionName: assetVersionName,
				AssetID:          assetID,
			},
		}
	}

	return vulns
}

// VulnInPackageToDependencyVulnsWithoutArtifact converts a vulnerability to multiple DependencyVuln objects
// based on all paths through the dependency graph.
func VulnInPackageToDependencyVulnsWithoutArtifact(vuln models.VulnInPackage, sbom *normalize.SBOMGraph, assetID uuid.UUID, assetVersionName string) []models.DependencyVuln {
	v := vuln
	// Unescape URL-encoded characters (e.g., %2B -> +) to match the format stored in the database
	stringPurl, _ := url.PathUnescape(v.Purl.ToString())
	fixedVersion := normalize.FixFixedVersion(stringPurl, v.FixedVersion)

	// Find all paths to this vulnerable component
	paths := sbom.FindAllPathsToPURL(stringPurl)

	// If no paths found, create a single vuln with empty path (fallback)
	if len(paths) == 0 {
		return []models.DependencyVuln{
			{
				Vulnerability: models.Vulnerability{
					AssetVersionName: assetVersionName,
					AssetID:          assetID,
				},
				CVEID:                 v.CVEID,
				ComponentPurl:         stringPurl,
				ComponentFixedVersion: fixedVersion,
				CVE:                   v.CVE,
				VulnerabilityPath:     []string{},
			},
		}
	}

	// Create one DependencyVuln per path (pre-allocate with known capacity)
	result := make([]models.DependencyVuln, 0, len(paths))
	for _, path := range paths {
		dependencyVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetVersionName: assetVersionName,
				AssetID:          assetID,
			},
			CVEID:                 v.CVEID,
			ComponentPurl:         stringPurl,
			ComponentFixedVersion: fixedVersion,
			CVE:                   v.CVE,
			VulnerabilityPath:     path.ToStringSliceComponentOnly(),
		}
		result = append(result, dependencyVuln)
	}

	return result
}
