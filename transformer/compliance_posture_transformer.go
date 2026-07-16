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
	"encoding/json"
	"strings"
	"time"

	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"gorm.io/datatypes"
)

func mustMarshalJSON(v any) datatypes.JSON {
	b, _ := json.Marshal(v)
	return datatypes.JSON(b)
}

func CompliancePostureToDTO(c models.CompliancePosture) dtos.CompliancePostureWithDetailsDTO {

	mappedControls := make([]dtos.MappedControlDTO, len(c.FrameworkControl.MappedControls))
	for i, m := range c.FrameworkControl.MappedControls {
		mappedControls[i] = dtos.MappedControlDTO{
			FrameworkControlID: m.FrameworkControlID,
			RelatedFramework:   m.RelatedFramework,
			RelatedControlID:   m.RelatedControlID,
		}
	}

	p := dtos.CompliancePostureWithControlDTO{
		FrameworkControlID:       c.FrameworkControlID,
		CompliancePostureID:      c.ID.String(),
		ControlID:                c.FrameworkControl.ControlID,
		Framework:                c.FrameworkControl.Framework,
		Title:                    c.FrameworkControl.Title,
		Description:              c.FrameworkControl.Description,
		Class:                    c.FrameworkControl.Class,
		Additional:               mustMarshalJSON(c.FrameworkControl.Additional),
		ParentFrameworkControlID: c.FrameworkControl.ParentFrameworkControlID,
		AssetVersionName:         c.AssetVersionName,
		AssetID:                  c.AssetID,
		ProjectID:                c.ProjectID,
		OrgID:                    &c.OrgID,
		State:                    c.State,
		TicketID:                 c.TicketID,
		TicketURL:                c.TicketURL,
		MappedControls:           mappedControls,
	}
	events := make([]dtos.VulnEventDTO, len(c.Events))
	for i, e := range c.Events {
		events[i] = ConvertVulnEventToDto(e)
	}
	return dtos.CompliancePostureWithDetailsDTO{
		CompliancePostureWithControlDTO: p,
		Events:                          events,
	}
}

func ConvertCompliancePosturesToSystemSecurityPlanOSCAL(compliancePostures []dtos.CompliancePostureWithDetailsDTO, frameworkControls []models.FrameworkControl) (oscalTypes.OscalCompleteSchema, error) {

	//OscalCompleteSchema
	var schema oscalTypes.OscalCompleteSchema
	systemSecurityPlan := oscalTypes.SystemSecurityPlan{}

	metadata := oscalTypes.Metadata{
		Title:        "DevGuard System Security Plan",
		Version:      "0.0.1",
		OscalVersion: "1.1.3",
		LastModified: time.Now(),
	}
	systemSecurityPlan.Metadata = metadata
	systemSecurityPlan.UUID = uuid.New().String()

	systemSecurityPlan.SystemCharacteristics = oscalTypes.SystemCharacteristics{
		SystemName:  "DevGuard System Security Plan",
		Description: "DevGuard System Security Plan",
		AuthorizationBoundary: oscalTypes.AuthorizationBoundary{
			Description: "DevGuard System Security Plan",
		},
		Status: oscalTypes.Status{
			State: "operational",
		},
		SystemIds: []oscalTypes.SystemId{
			{
				ID: uuid.New().String(),
			},
		},

		SystemInformation: oscalTypes.SystemInformation{
			InformationTypes: []oscalTypes.InformationType{
				{
					UUID:        uuid.New().String(),
					Title:       "DevGuard Compliance Data",
					Description: "Compliance posture data managed by DevGuard.",
				},
			},
		},
	}

	systemImplementation := oscalTypes.SystemImplementation{
		Users: []oscalTypes.SystemUser{
			{
				UUID:  uuid.New().String(),
				Title: "DevGuard User",
			},
		},
	}

	systemComponent := oscalTypes.SystemComponent{
		UUID:        uuid.New().String(),
		Title:       "DevGuard System Component",
		Description: "This component represents the DevGuard system responsible for managing compliance posture data.",
		Status: oscalTypes.SystemComponentStatus{
			State: "operational",
		},
		Type: "software",
	}
	components := []oscalTypes.SystemComponent{
		// only a single component for now, - this system, like trestle is doing it
		systemComponent,
	}

	systemImplementation.Components = components
	systemSecurityPlan.SystemImplementation = systemImplementation

	controlImplementation := oscalTypes.ControlImplementation{}
	implementedRequirements := []oscalTypes.ImplementedRequirement{}

	for _, compliancePosture := range compliancePostures {
		implementedRequirement := oscalTypes.ImplementedRequirement{
			ControlId: strings.ReplaceAll(strings.ReplaceAll(compliancePosture.FrameworkControlID, "++", ""), ":", "_"),

			UUID: uuid.NewSHA1(uuid.NameSpaceURL, []byte(compliancePosture.CompliancePostureID)).String(),
		}

		description := ""
		state := string(compliancePosture.State)
		if state == "open" {
			state = "planned"
		}
		if len(compliancePosture.Events) > 0 && compliancePosture.Events[len(compliancePosture.Events)-1].Justification != nil {
			description = *compliancePosture.Events[len(compliancePosture.Events)-1].Justification
		}
		byComponents := []oscalTypes.ByComponent{}
		byComponent := oscalTypes.ByComponent{
			ComponentUuid: systemComponent.UUID,
			Description:   description,
			ImplementationStatus: &oscalTypes.ImplementationStatus{
				State: state,
			},
			UUID: uuid.NewSHA1(uuid.NameSpaceURL, []byte(compliancePosture.CompliancePostureID)).String(),
		}
		byComponents = append(byComponents, byComponent)
		implementedRequirement.ByComponents = &byComponents

		implementedRequirements = append(implementedRequirements, implementedRequirement)
	}

	controlImplementation.ImplementedRequirements = implementedRequirements
	systemSecurityPlan.ControlImplementation = controlImplementation

	schema.SystemSecurityPlan = &systemSecurityPlan

	return schema, nil
}
