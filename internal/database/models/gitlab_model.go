// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package models

import (
	"time"

	"github.com/google/uuid"
)

type GitLabOauth2Token struct {
	ID uuid.UUID `json:"id" gorm:"column:id;primaryKey;default:gen_random_uuid()"` // the id of the token
	// oauth2 token using GitLab Applications feature
	AccessToken  string    `json:"accessToken" gorm:"column:access_token"`
	RefreshToken string    `json:"refreshToken" gorm:"column:refresh_token"`
	ExpiresAt    int64     `json:"expiresAt" gorm:"column:expires_at"`
	Scopes       string    `json:"scopes" gorm:"column:scopes"`
	UserID       string    `json:"userId" gorm:"column:user_id;uniqueIndex:single-api-scope-token"` // the gitlab user id
	GitLabUserID int       `json:"gitLabUserId" gorm:"column:gitlab_user_id"`                       // the gitlab user id
	Expiry       time.Time `json:"expiry" gorm:"column:expiry"`
	Verifier     *string   `json:"verifier" gorm:"column:verifier"`                                   // used for the PKCE to protect against CSRF attacks during doing oauth2
	BaseURL      string    `json:"baseUrl" gorm:"column:base_url;uniqueIndex:single-api-scope-token"` // the base url of the gitlab instance
	CreatedAt    time.Time `json:"createdAt" gorm:"column:created_at"`
	UpdatedAt    time.Time `json:"updatedAt" gorm:"column:updated_at"`
}

func (GitLabOauth2Token) TableName() string {
	return "gitlab_oauth2_tokens"
}

type GitLabIntegration struct {
	Model

	Name string `json:"name"`

	AccessToken string `json:"accessToken"`
	GitLabUrl   string `json:"gitLabUrl" gorm:"column:gitlab_url"`

	Org   Org       `json:"org" gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE;"`
	OrgID uuid.UUID `json:"orgId" gorm:"column:org_id"`
}

func (GitLabIntegration) TableName() string {
	return "gitlab_integrations"
}
