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

package dto

import (
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/flawfix/internal/models"
)

type OrganizationCreateRequest struct {
	Name                   string  `json:"name" validate:"required"`
	ContactPhoneNumber     *string `json:"contactPhoneNumber"`
	NumberOfEmployees      *int    `json:"numberOfEmployees"`
	Country                *string `json:"country"`
	Industry               *string `json:"industry"`
	CriticalInfrastructure bool    `json:"criticalInfrastructure"`
	ISO27001               bool    `json:"iso27001"`
	NIST                   bool    `json:"nist"`
	Grundschutz            bool    `json:"grundschutz"`
}

func (o *OrganizationCreateRequest) ToModel() models.Organization {
	return models.Organization{
		Name:                   o.Name,
		ContactPhoneNumber:     o.ContactPhoneNumber,
		NumberOfEmployees:      o.NumberOfEmployees,
		Country:                o.Country,
		Industry:               o.Industry,
		CriticalInfrastructure: o.CriticalInfrastructure,
		ISO27001:               o.ISO27001,
		NIST:                   o.NIST,
		Grundschutz:            o.Grundschutz,
		Slug:                   slug.Make(o.Name),
	}
}
