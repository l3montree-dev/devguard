// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package models

import (
	"github.com/google/uuid"
)

type WebhookIntegration struct {
	Model
	Name        *string `json:"name"`
	Description *string `json:"description"`
	URL         string  `json:"url" gorm:"column:url"`
	Secret      *string `json:"secret" gorm:"column:secret"`
	SbomEnabled bool    `json:"sbomEnabled" gorm:"column:sbom_enabled"`
	VulnEnabled bool    `json:"vulnEnabled" gorm:"column:vuln_enabled"`

	Org   Org       `json:"org" gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE;"`
	OrgID uuid.UUID `json:"orgId" gorm:"column:org_id"`

	ProjectID *uuid.UUID `json:"projectId" gorm:"column:project_id;nullable"`
	Project   *Project   `json:"project" gorm:"foreignKey:ProjectID;constraint:OnDelete:CASCADE;"`
}

func (WebhookIntegration) TableName() string {
	return "webhook_integrations"
}
