// Copyright (C) 2025 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package transformer

import (
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

func OrgCreateRequestToModel(c dtos.OrgCreateRequest) models.Org {

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

func ApplyOrgPatchRequestToModel(p dtos.OrgPatchRequest, org *models.Org) bool {
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

func obfuscateGitLabIntegrations(integration models.GitLabIntegration) dtos.GitlabIntegrationDTO {
	return dtos.GitlabIntegrationDTO{
		ID:              integration.ID.String(),
		Name:            integration.Name,
		ObfuscatedToken: integration.AccessToken[:4] + "************" + integration.AccessToken[len(integration.AccessToken)-4:],
		URL:             integration.GitLabURL,
	}
}

func obfuscateJiraIntegrations(integration models.JiraIntegration) dtos.JiraIntegrationDTO {
	return dtos.JiraIntegrationDTO{
		ID:              integration.ID.String(),
		Name:            integration.Name,
		ObfuscatedToken: integration.AccessToken[:4] + "************" + integration.AccessToken[len(integration.AccessToken)-4:],
		URL:             integration.URL,
		UserEmail:       integration.UserEmail,
	}
}

func obfuscateWebhookIntegrations(integration models.WebhookIntegration) dtos.WebhookIntegrationDTO {
	return dtos.WebhookIntegrationDTO{
		ID:          integration.ID.String(),
		Name:        *integration.Name,
		Description: *integration.Description,
		URL:         integration.URL,
		SbomEnabled: integration.SbomEnabled,
		VulnEnabled: integration.VulnEnabled,
	}
}

func OrgDTOFromModel(org models.Org) dtos.OrgDTO {
	return dtos.OrgDTO{
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
