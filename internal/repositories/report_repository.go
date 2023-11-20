// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package repositories

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/owenrumney/go-sarif/sarif"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type GormReportRepository struct {
	db            *gorm.DB
	appRepository *GormApplicationRepository
}

func NewGormReportRepository(db *gorm.DB, appRepository *GormApplicationRepository) *GormReportRepository {
	return &GormReportRepository{
		db:            db,
		appRepository: appRepository,
	}
}

func transformLocations2Map(locations []*sarif.Location) datatypes.JSON {
	res := make([]map[string]any, len(locations))
	for i, location := range locations {
		res[i] = map[string]any{
			"message": map[string]any{
				"text": location.Message.Text,
			},
			"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{
					"uri": location.PhysicalLocation.ArtifactLocation.URI,
				},
				"region": map[string]any{
					"startLine":   location.PhysicalLocation.Region.StartLine,
					"endLine":     location.PhysicalLocation.Region.EndLine,
					"startColumn": location.PhysicalLocation.Region.StartColumn,
					"endColumn":   location.PhysicalLocation.Region.EndColumn,
				},
			},
		}
	}
	// print formatted json
	b, err := json.Marshal(res)
	if err != nil {
		return datatypes.JSON{}
	}

	return datatypes.JSON(b)
}

func (s *GormReportRepository) SaveSarifReport(appName string, report *sarif.Report) ([]models.Report, error) {
	// check if the application does already exist
	app, err := s.appRepository.FindOrCreate(nil, appName)
	if err != nil {
		return nil, err
	}

	runs := make([]models.Report, len(report.Runs))

	for _, runReport := range report.Runs {
		run := models.Report{ApplicationID: app.ID,
			DriverName:           runReport.Tool.Driver.Name,
			DriverVersion:        runReport.Tool.Driver.Version,
			DriverInformationUri: runReport.Tool.Driver.InformationURI,
		}
		for _, result := range runReport.Results {
			run.Results = append(run.Results, models.Result{
				Level:     result.Level,
				Message:   result.Message.Text,
				RuleID:    result.RuleID,
				Locations: transformLocations2Map(result.Locations),
			})
		}
		err := s.db.Create(&run).Error
		if err != nil {
			return nil, err
		}

		runs = append(runs, run)
	}

	return runs, nil
}

func (s *GormReportRepository) Delete(id uuid.UUID) error {
	return s.db.Delete(&models.Report{}, id).Error
}

func (s *GormReportRepository) Read(id uuid.UUID) (models.Report, error) {
	var report models.Report
	err := s.db.First(&report, id).Error
	if err != nil {
		return report, err
	}
	return report, nil
}

func (s *GormReportRepository) Update(report *models.Report) error {
	return s.db.Save(report).Error
}
