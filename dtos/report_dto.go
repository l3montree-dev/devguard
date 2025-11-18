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

package dtos

type YamlVars struct {
	DocumentTitle    string `yaml:"document_title"`
	PrimaryColor     string `yaml:"primary_color"`
	Version          string `yaml:"version"`
	TimeOfGeneration string `yaml:"generation_date"`
	ProjectTitle1    string `yaml:"app_title_part_one"`
	ProjectTitle2    string `yaml:"app_title_part_two"`
	OrganizationName string `yaml:"organization_name"`
	Integrity        string `yaml:"integrity"`
}

type YamlMetadata struct {
	Vars YamlVars `yaml:"metadata_vars"`
}
