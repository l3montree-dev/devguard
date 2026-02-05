// Copyright 2026 larshermges
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

type NPMResponse struct {
	ID             string                 `json:"_id"`
	Rev            string                 `json:"_rev"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	DistTags       DistTags               `json:"dist-tags"`
	Versions       map[string]VersionData `json:"versions"`
	Time           map[string]string      `json:"time"`
	Bugs           Bugs                   `json:"bugs"`
	Author         Person                 `json:"author"`
	License        string                 `json:"license"`
	Homepage       string                 `json:"homepage"`
	Keywords       []string               `json:"keywords"`
	Repository     Repository             `json:"repository"`
	Contributors   []Person               `json:"contributors"`
	Maintainers    []Person               `json:"maintainers"`
	ReadMe         string                 `json:"readme"`
	ReadMeFilename string                 `json:"readmeFilename"`
	Users          map[string]bool        `json:"users"`
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
	Engines      []string               `json:"engines"`
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
	KeyId string `json:"keyid"`
}
