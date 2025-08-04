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

package org

import (
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type acceptInvitationRequest struct {
	Code string `json:"code" validate:"required"`
}

type inviteRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type changeRoleRequest struct {
	Role string `json:"role" validate:"required,oneof=member admin"`
}

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
	Language               string  `json:"language"`
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
		Language:               c.Language,
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

	ShareVulnInformation *bool           `json:"shareVulnInformation"`
	IsPublic             *bool           `json:"isPublic"`
	ConfigFiles          *map[string]any `json:"configFiles"`
	Language             *string         `json:"language"`
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

	if p.ShareVulnInformation != nil {
		updated = true
		org.SharesVulnInformation = *p.ShareVulnInformation
	}

	if p.IsPublic != nil {
		updated = true
		org.IsPublic = *p.IsPublic
	}

	if p.ConfigFiles != nil {
		updated = true
		org.ConfigFiles = *p.ConfigFiles
	}

	if p.Language != nil && utils.CheckForValidLanguageCode(*p.Language) {
		updated = true
		org.Language = *p.Language
	}

	return updated

}

type OrgDTO struct {
	models.Model
	Name                   string           `json:"name" gorm:"type:text"`
	ContactPhoneNumber     *string          `json:"contactPhoneNumber" gorm:"type:text"`
	NumberOfEmployees      *int             `json:"numberOfEmployees"`
	Country                *string          `json:"country" gorm:"type:text"`
	Industry               *string          `json:"industry" gorm:"type:text"`
	CriticalInfrastructure bool             `json:"criticalInfrastructure"`
	ISO27001               bool             `json:"iso27001"`
	NIST                   bool             `json:"nist"`
	Grundschutz            bool             `json:"grundschutz"`
	Projects               []models.Project `json:"projects" gorm:"foreignKey:OrganizationID;"`
	Slug                   string           `json:"slug" gorm:"type:text;unique;not null;index"`
	Description            string           `json:"description" gorm:"type:text"`

	GithubAppInstallations []models.GithubAppInstallation `json:"githubAppInstallations" gorm:"foreignKey:OrgID;"`

	GitLabIntegrations []common.GitlabIntegrationDTO `json:"gitLabIntegrations" gorm:"foreignKey:OrgID;"`

	JiraIntegrations []common.JiraIntegrationDTO `json:"jiraIntegrations" gorm:"foreignKey:OrgID;"`

	SharesVulnInformation bool                           `json:"sharesVulnInformation"`
	IsPublic              bool                           `json:"isPublic" gorm:"default:false;"`
	Webhooks              []common.WebhookIntegrationDTO `json:"webhooks" gorm:"foreignKey:OrgID;"`

	ConfigFiles map[string]any `json:"configFiles"`

	Language                 string  `json:"language"`
	ExternalEntityProviderID *string `json:"externalEntityProviderId" gorm:"type:text"`
}

func obfuscateGitLabIntegrations(integration models.GitLabIntegration) common.GitlabIntegrationDTO {
	return common.GitlabIntegrationDTO{
		ID:              integration.ID.String(),
		Name:            integration.Name,
		ObfuscatedToken: integration.AccessToken[:4] + "************" + integration.AccessToken[len(integration.AccessToken)-4:],
		URL:             integration.GitLabURL,
	}
}

func obfuscateJiraIntegrations(integration models.JiraIntegration) common.JiraIntegrationDTO {
	return common.JiraIntegrationDTO{
		ID:              integration.ID.String(),
		Name:            integration.Name,
		ObfuscatedToken: integration.AccessToken[:4] + "************" + integration.AccessToken[len(integration.AccessToken)-4:],
		URL:             integration.URL,
		UserEmail:       integration.UserEmail,
	}
}

func obfuscateWebhookIntegrations(integration models.WebhookIntegration) common.WebhookIntegrationDTO {
	return common.WebhookIntegrationDTO{
		ID:          integration.ID.String(),
		Name:        *integration.Name,
		Description: *integration.Description,
		URL:         integration.URL,
		SbomEnabled: integration.SbomEnabled,
		VulnEnabled: integration.VulnEnabled,
	}
}

func FromModel(org models.Org) OrgDTO {
	return OrgDTO{
		Model:                  org.Model,
		Name:                   org.Name,
		ContactPhoneNumber:     org.ContactPhoneNumber,
		NumberOfEmployees:      org.NumberOfEmployees,
		Country:                org.Country,
		Industry:               org.Industry,
		CriticalInfrastructure: org.CriticalInfrastructure,
		ISO27001:               org.ISO27001,
		NIST:                   org.NIST,
		Grundschutz:            org.Grundschutz,
		Slug:                   org.Slug,
		Description:            org.Description,
		SharesVulnInformation:  org.SharesVulnInformation,
		IsPublic:               org.IsPublic,

		Projects:                 org.Projects,
		GithubAppInstallations:   org.GithubAppInstallations,
		GitLabIntegrations:       utils.Map(org.GitLabIntegrations, obfuscateGitLabIntegrations),
		JiraIntegrations:         utils.Map(org.JiraIntegrations, obfuscateJiraIntegrations),
		Webhooks:                 utils.Map(org.Webhooks, obfuscateWebhookIntegrations),
		ConfigFiles:              org.ConfigFiles,
		Language:                 org.Language,
		ExternalEntityProviderID: org.ExternalEntityProviderID,
	}
}

type orgDetailsDTO struct {
	OrgDTO
	Members []core.User `json:"members"`
}
