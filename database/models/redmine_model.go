// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package models

import "github.com/google/uuid"

type RedmineIntegration struct {
	Model

	Name  string    `json:"name" gorm:"type:varchar(255);not null"`
	Org   Org       `json:"org" gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE;"`
	OrgID uuid.UUID `json:"orgId" gorm:"column:org_id"`

	AccessToken string `json:"-"`
	URL         string `json:"url" gorm:"type:text;not null"`

	TrackerID       int  `json:"trackerId" gorm:"column:tracker_id;not null"`
	DefaultStatusID *int `json:"defaultStatusId" gorm:"column:default_status_id"`
	CloseStatusID   *int `json:"closeStatusId" gorm:"column:close_status_id"`

	LowPriorityID      *int `json:"lowPriorityId" gorm:"column:low_priority_id"`
	MediumPriorityID   *int `json:"mediumPriorityId" gorm:"column:medium_priority_id"`
	HighPriorityID     *int `json:"highPriorityId" gorm:"column:high_priority_id"`
	CriticalPriorityID *int `json:"criticalPriorityId" gorm:"column:critical_priority_id"`

	MermaidIntegration MermaidIntegrationType `json:"mermaidIntegration" gorm:"type:text;not null;default:'none'"`
}

func (RedmineIntegration) TableName() string {
	return "redmine_integrations"
}

type MermaidIntegrationType string

const (
	None       MermaidIntegrationType = "none"
	Macro      MermaidIntegrationType = "macro"
	CommonMark MermaidIntegrationType = "commonmark"
)
