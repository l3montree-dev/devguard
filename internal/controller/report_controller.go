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

package controller

import (
	"io"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/helpers"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/labstack/echo/v4"
	"github.com/owenrumney/go-sarif/sarif"
)

type reportRepository interface {
	SaveSarifReport(applicationID string, report *sarif.Report) ([]models.Report, error)
	Delete(uuid.UUID) error
	Read(uuid.UUID) (models.Report, error)
	Update(*models.Report) error
}

type ReportController struct {
	reportRepository
}

func NewReportController(repository reportRepository) *ReportController {
	return &ReportController{
		reportRepository: repository,
	}
}

func (r *ReportController) Create(c echo.Context) error {
	// print the request body as string
	reportStr, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return err
	}
	report, err := sarif.FromBytes(reportStr)
	if err != nil {
		return err
	}

	applicationID, err := helpers.GetApplicationID(c)
	if err != nil {
		return echo.NewHTTPError(500, "could not get application id").WithInternal(err)
	}
	// save the report inside the database
	reports, err := r.SaveSarifReport(applicationID.String(), report)

	if err != nil {
		return echo.NewHTTPError(500, "could not save report").WithInternal(err)
	}

	return c.JSON(200, reports)
}

func (r *ReportController) Delete(c echo.Context) error {
	reportID, err := uuid.Parse(c.Param("reportID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid report id").WithInternal(err)
	}

	err = r.reportRepository.Delete(reportID)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete report").WithInternal(err)
	}

	return c.NoContent(200)
}

func (r *ReportController) Read(c echo.Context) error {
	reportID, err := uuid.Parse(c.Param("reportID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid report id").WithInternal(err)
	}

	report, err := r.reportRepository.Read(reportID)
	if err != nil {
		return echo.NewHTTPError(500, "could not read report").WithInternal(err)
	}

	return c.JSON(200, report)
}

func (r *ReportController) Update(c echo.Context) error {
	reportID, err := uuid.Parse(c.Param("reportID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid report id").WithInternal(err)
	}

	report, err := r.reportRepository.Read(reportID)
	if err != nil {
		return echo.NewHTTPError(500, "could not read report").WithInternal(err)
	}

	// update the report
	err = c.Bind(&report)
	if err != nil {
		return echo.NewHTTPError(500, "could not bind report").WithInternal(err)
	}

	err = r.reportRepository.Update(&report)
	if err != nil {
		return echo.NewHTTPError(500, "could not update report").WithInternal(err)
	}

	return c.JSON(200, map[string]string{
		"message": "report updated",
	})
}
