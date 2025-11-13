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
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

func CVEToDTO(cve *models.CVE) *dtos.CVEDTO {
	if cve == nil {
		return nil
	}
	return &dtos.CVEDTO{
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
		ComponentDepth:        f.ComponentDepth,
		ComponentFixedVersion: f.ComponentFixedVersion,
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
