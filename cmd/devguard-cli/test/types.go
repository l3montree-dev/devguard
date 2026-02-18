// Copyright (C) 2026 l3montree GmbH
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

package main

type NPMResponse struct {
	ID                   string                 `json:"_id"`
	Rev                  string                 `json:"_rev"`
	Name                 string                 `json:"name"`
	Description          string                 `json:"description"`
	DistTags             DistTags               `json:"dist-tags"`
	Versions             map[string]VersionData `json:"versions"`
	Time                 map[string]string      `json:"time"`
	Bugs                 Bugs                   `json:"bugs"`
	Author               Person                 `json:"author"`
	License              string                 `json:"license"`
	Homepage             string                 `json:"homepage"`
	Keywords             []string               `json:"keywords"`
	Repository           Repository             `json:"repository"`
	Contributors         []Person               `json:"contributors"`
	Maintainers          []Person               `json:"maintainers"`
	ReadMe               string                 `json:"readme"`
	ReadMeFilename       string                 `json:"readmeFilename"`
	Users                map[string]bool        `json:"users"`
	Dependencies         map[string]string      `json:"dependencies"`
	DevDependencies      map[string]string      `json:"devDependencies"`
	PeerDependencies     map[string]string      `json:"peerDependencies"`
	OptionalDependencies map[string]string      `json:"optionalDependencies"`
}

type DistTags struct {
	Latest string `json:"latest"`
}

type VersionData struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Keywords     []string               `json:"keywords"`
	Author       Person                 `json:"author"`
	License      string                 `json:"license"`
	ID           string                 `json:"_id"`
	Maintainers  []Person               `json:"maintainers"`
	Contributors []Person               `json:"contributors"`
	Homepage     string                 `json:"homepage"`
	Bugs         Bugs                   `json:"bugs"`
	Jam          map[string]interface{} `json:"jam"`
	Dist         Dist                   `json:"dist"`
	Main         string                 `json:"main"`
	From         string                 `json:"from"`
	Engines      interface{}            `json:"engines"`
	NpmUser      Person                 `json:"_npmUser"`
	Repository   Repository             `json:"repository"`
	NpmVersion   string                 `json:"_npmVersion"`
	Description  string                 `json:"description"`
	Directories  map[string]string      `json:"directories"`
}

type Person struct {
	URL   string `json:"url"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Bugs struct {
	URL string `json:"url"`
}

type Dist struct {
	Shasum     string       `json:"shasum"`
	Tarball    string       `json:"tarball"`
	Integrity  string       `json:"integrity"`
	Signatures []Signatures `json:"signatures"`
}

type Repository struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

type Signatures struct {
	Sig   string `json:"sig"`
	KeyID string `json:"keyid"`
}
