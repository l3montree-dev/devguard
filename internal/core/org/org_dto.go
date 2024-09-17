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

package org

import (
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type createRequest struct {
	Name                   string  `json:"name" validate:"required"`
	ContactPhoneNumber     *string `json:"contactPhoneNumber"`
	NumberOfEmployees      *int    `json:"numberOfEmployees"`
	Country                *string `json:"country"`
	Industry               *string `json:"industry"`
	CriticalInfrastructure bool    `json:"criticalInfrastructure"`
	ISO27001               bool    `json:"iso27001"`
	NIST                   bool    `json:"nist"`
	Grundschutz            bool    `json:"grundschutz"`
	Description            string  `json:"description"`
}

func (c createRequest) toModel() models.Org {

	return models.Org{
		Name:                   c.Name,
		ContactPhoneNumber:     c.ContactPhoneNumber,
		NumberOfEmployees:      c.NumberOfEmployees,
		Country:                c.Country,
		Industry:               c.Industry,
		CriticalInfrastructure: c.CriticalInfrastructure,
		ISO27001:               c.ISO27001,
		NIST:                   c.NIST,
		Grundschutz:            c.Grundschutz,
		Slug:                   slug.Make(c.Name),
	}
}

type patchRequest struct {
	Name                   *string `json:"name"`
	ContactPhoneNumber     *string `json:"contactPhoneNumber"`
	NumberOfEmployees      *int    `json:"numberOfEmployees"`
	Country                *string `json:"country"`
	Industry               *string `json:"industry"`
	CriticalInfrastructure *bool   `json:"criticalInfrastructure"`
	ISO27001               *bool   `json:"iso27001"`
	NIST                   *bool   `json:"nist"`
	Grundschutz            *bool   `json:"grundschutz"`
	Description            *string `json:"description"`

	IsPublic *bool `json:"isPublic"`
}

func (p patchRequest) applyToModel(org *models.Org) bool {
	updated := false

	if p.Name != nil {
		updated = true
		org.Name = *p.Name
		org.Slug = slug.Make(*p.Name)
	}

	if p.ContactPhoneNumber != nil {
		updated = true
		org.ContactPhoneNumber = p.ContactPhoneNumber
	}

	if p.NumberOfEmployees != nil {
		updated = true
		org.NumberOfEmployees = p.NumberOfEmployees
	}

	if p.Country != nil {
		updated = true
		org.Country = p.Country
	}

	if p.Industry != nil {
		updated = true
		org.Industry = p.Industry
	}

	if p.CriticalInfrastructure != nil {
		updated = true
		org.CriticalInfrastructure = *p.CriticalInfrastructure
	}

	if p.ISO27001 != nil {
		updated = true
		org.ISO27001 = *p.ISO27001
	}

	if p.NIST != nil {
		updated = true
		org.NIST = *p.NIST
	}

	if p.Grundschutz != nil {
		updated = true
		org.Grundschutz = *p.Grundschutz
	}

	if p.Description != nil {
		updated = true
		org.Description = *p.Description
	}

	if p.IsPublic != nil {
		updated = true
		org.IsPublic = *p.IsPublic
	}

	return updated

}

type orgDetails struct {
	models.Org
	Members []core.User `json:"members"`
}
