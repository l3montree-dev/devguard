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

package dtos

// PermalinkResponse answers "which slugs does this UUID belong to?". The
// frontend turns it into the slug based URL a permalink redirects to, so the
// project and asset fields stay empty for the levels that do not apply.
type PermalinkResponse struct {
	OrganizationSlug string `json:"organizationSlug"`
	ProjectSlug      string `json:"projectSlug,omitempty"`
	AssetSlug        string `json:"assetSlug,omitempty"`
}
