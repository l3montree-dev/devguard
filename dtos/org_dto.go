// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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

package dtos

import (
	"time"

	"github.com/google/uuid"
)

type AcceptInvitationRequest struct {
	Code string `json:"code" validate:"required,max=256"`
}

type InviteRequest struct {
	Email string `json:"email" validate:"required,email,max=320"`
}

type OrgChangeRoleRequest struct {
	Role string `json:"role" validate:"required,oneof=member admin"`
}

type OrgCreateRequest struct {
	Name                   string  `json:"name" validate:"required,max=256"`
	ContactPhoneNumber     *string `json:"contactPhoneNumber" validate:"omitempty,max=256"`
	NumberOfEmployees      *int    `json:"numberOfEmployees"`
	Country                *string `json:"country" validate:"omitempty,max=256"`
	Industry               *string `json:"industry" validate:"omitempty,max=256"`
	CriticalInfrastructure bool    `json:"criticalInfrastructure"`
	ISO27001               bool    `json:"iso27001"`
	NIST                   bool    `json:"nist"`
	Grundschutz            bool    `json:"grundschutz"`
	Description            string  `json:"description" validate:"max=4000"`
	Language               string  `json:"language" validate:"max=256"`
}

type OrgPatchRequest struct {
	Name                   *string `json:"name" validate:"omitempty,max=256"`
	ContactPhoneNumber     *string `json:"contactPhoneNumber" validate:"omitempty,max=256"`
	NumberOfEmployees      *int    `json:"numberOfEmployees"`
	Country                *string `json:"country" validate:"omitempty,max=256"`
	Industry               *string `json:"industry" validate:"omitempty,max=256"`
	CriticalInfrastructure *bool   `json:"criticalInfrastructure"`
	ISO27001               *bool   `json:"iso27001"`
	NIST                   *bool   `json:"nist"`
	Grundschutz            *bool   `json:"grundschutz"`
	Description            *string `json:"description" validate:"omitempty,max=4000"`

	ShareVulnInformation *bool           `json:"shareVulnInformation"`
	IsPublic             *bool           `json:"isPublic"`
	ConfigFiles          *map[string]any `json:"configFiles"`
	Language             *string         `json:"language" validate:"omitempty,max=256"`
}

type GithubAppInstallation struct {
	InstallationID                         int `json:"installationId"`
	OrgID                                  uuid.UUID
	InstallationCreatedWebhookReceivedTime time.Time `json:"installationCreatedWebhookReceivedTime"`
	SettingsURL                            string    `json:"settingsUrl"`
	TargetType                             string    `json:"targetType"`
	TargetLogin                            string    `json:"targetLogin"`
	TargetAvatarURL                        string    `json:"targetAvatarUrl"`
}

type Org struct {
	ID                     uuid.UUID `json:"id"`
	CreatedAt              time.Time `json:"createdAt"`
	UpdatedAt              time.Time `json:"updatedAt"`
	Name                   string    `json:"name" gorm:"type:text"`
	ContactPhoneNumber     *string   `json:"contactPhoneNumber" gorm:"type:text"`
	NumberOfEmployees      *int      `json:"numberOfEmployees"`
	Country                *string   `json:"country" gorm:"type:text"`
	Industry               *string   `json:"industry" gorm:"type:text"`
	CriticalInfrastructure bool      `json:"criticalInfrastructure"`
	ISO27001               bool      `json:"iso27001"`
	NIST                   bool      `json:"nist"`
	Grundschutz            bool      `json:"grundschutz"`
	Projects               []Project `json:"projects" gorm:"foreignKey:OrganizationID;"`
	Slug                   string    `json:"slug" gorm:"type:text;unique;not null;index"`
	Description            string    `json:"description" gorm:"type:text"`

	GithubAppInstallations []GithubAppInstallation `json:"githubAppInstallations" gorm:"foreignKey:OrgID;"`

	GitLabIntegrations []GitlabIntegration `json:"gitLabIntegrations" gorm:"foreignKey:OrgID;"`

	JiraIntegrations []JiraIntegration `json:"jiraIntegrations" gorm:"foreignKey:OrgID;"`

	SharesVulnInformation    bool           `json:"sharesVulnInformation"`
	IsPublic                 bool           `json:"isPublic" gorm:"default:false;"`
	ConfigFiles              map[string]any `json:"configFiles"`
	Language                 string         `json:"language"`
	ExternalEntityProviderID *string        `json:"externalEntityProviderId" gorm:"type:text"`
}

type OrgDetails struct {
	Org
	Members        []User        `json:"members"`
	InvitedMembers []InvitedUser `json:"invitedMembers"`
}

type OrgSettings struct {
	OrgDetails
	Webhooks []WebhookIntegration `json:"webhooks"`
}
