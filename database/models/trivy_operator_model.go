// Copyright (C) 2026 l3montree GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "github.com/google/uuid"

type TrivyOperatorIntegration struct {
	Model

	Name      string    `json:"name" gorm:"type:varchar(255);not null"`
	ClusterID string    `json:"clusterId" gorm:"column:cluster_id;type:varchar(255);not null;uniqueIndex:uq_trivy_operator_cluster_org"`
	Secret    string    `json:"secret" gorm:"type:text;not null"`
	Org       Org       `json:"-" gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE;"`
	OrgID     uuid.UUID `json:"orgId" gorm:"column:org_id;uniqueIndex:uq_trivy_operator_cluster_org"`
}

func (TrivyOperatorIntegration) TableName() string {
	return "trivy_operator_integrations"
}
