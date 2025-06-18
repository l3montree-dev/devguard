// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package models

import "github.com/google/uuid"

type JiraIntegration struct {
	Model

	Name  string    `json:"name" gorm:"type:varchar(255);not null"`
	Org   Org       `json:"org" gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE;"`
	OrgID uuid.UUID `json:"orgId" gorm:"column:org_id"`

	AccessToken string `json:"accessToken"`
	URL         string `json:"url" gorm:"type:text;not null"`
	UserEmail   string `json:"userEmail" gorm:"column:user_email"`
}

func (JiraIntegration) TableName() string {
	return "jira_integrations"
}
