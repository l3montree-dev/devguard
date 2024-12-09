// Copyright 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package models

import "github.com/google/uuid"

type Invitation struct {
	Model
	Code string `json:"code"`
	// OrganizationID is the ID of the organization the invitation is for
	OrganizationID uuid.UUID `json:"organizationId"`
	Organization   Org
	// Email is the email address of the user the invitation is for
	Email string `json:"email"`
}

func (i Invitation) TableName() string {
	return "invitations"
}
