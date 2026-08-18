// Copyright (C) 2026 l3montree GmbH
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

package controllers

import "github.com/l3montree-dev/devguard/shared"

// ExternalEntityProviderController gives the interface's multiple provider
// implementations (GitLab, GitHub, ...) a traceable route handler.
type ExternalEntityProviderController struct {
	service shared.ExternalEntityProviderService
}

func NewExternalEntityProviderController(service shared.ExternalEntityProviderService) *ExternalEntityProviderController {
	return &ExternalEntityProviderController{service: service}
}

// @Summary Trigger a sync for the current session's org
// @Tags Organizations
// @Security CookieAuth
// @Security PATAuth
// @Success 200
// @Router /trigger-sync [get]
func (e *ExternalEntityProviderController) TriggerOrgSync(c shared.Context) error {
	return e.service.TriggerOrgSync(c)
}

// @Summary Trigger a sync for the given org
// @Tags Organizations
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Success 200
// @Router /organizations/{organization}/trigger-sync [get]
func (e *ExternalEntityProviderController) TriggerSync(c shared.Context) error {
	return e.service.TriggerSync(c)
}
