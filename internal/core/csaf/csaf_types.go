// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later string.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package csaf

// root struct of the document
type csaf struct {
	Document        documentObject  `json:"document"`
	ProductTree     *productTree    `json:"product_tree,omitempty"`
	Vulnerabilities []vulnerability `json:"vulnerabilities,omitempty"`
}

// only mandatory parent category
type documentObject struct {
	Acknowledgements  *acknowledgements `json:"acknowledgements,omitempty"`
	AggregateSeverity *struct {
		Namespace string `json:"namespace,omitempty"`
		Text      string `json:"text,omitempty"`
	} `json:"aggregate_severity,omitempty"`
	Category       string         `json:"category,omitempty"`    //mandatory
	CSAFVersion    string         `json:"csaf_string,omitempty"` //mandatory
	Distribution   *distribution  `json:"distribution,omitempty"`
	Language       *string        `json:"lang,omitempty"`
	Notes          []note         `json:"notes,omitempty"`
	Publisher      publisher      `json:"publisher,omitempty"` //mandatory
	References     []reference    `json:"references,omitempty"`
	SourceLanguage *string        `json:"source_lang,omitempty"`
	Title          string         `json:"title,omitempty"`    //mandatory
	Tracking       trackingObject `json:"tracking,omitempty"` //mandatory
}

type trackingObject struct {
	Aliases            []string `json:"aliases,omitempty"`
	CurrentReleaseDate string   `json:"current_release_date,omitempty"` //mandatory
	Generator          *struct {
		Date   string `json:"date,omitempty"`
		Engine struct {
			Name    string `json:"name,omitempty"`
			Version string `json:"string,omitempty"`
		} `json:"engine,omitempty"`
	} `json:"generator,omitempty"`
	ID                 string     `json:"id,omitempty"`                   //mandatory
	InitialReleaseDate string     `json:"initial_release_date,omitempty"` //mandatory
	RevisionHistory    []revision `json:"revision_history,omitempty"`
	Status             string     `json:"status,omitempty"` //mandatory
	Version            string     `json:"string,omitempty"` //mandatory
}

type distribution struct {
	Text string `json:"text,omitempty"`
	TLP  struct {
		Label string `json:"label,omitempty"`
		URL   string `json:"url,omitempty"`
	} `json:"tlp,omitempty"`
}

type publisher struct {
	Category         string `json:"category,omitempty"` //mandatory
	ContactDetails   string `json:"contact_details,omitempty"`
	IssuingAuthority string `json:"issuing_authority,omitempty"`
	Name             string `json:"name,omitempty"`      //mandatory
	Namespace        string `json:"namespace,omitempty"` //mandatory
}

type revision struct {
	Date          string `json:"date,omitempty"` //mandatory
	LegacyVersion string `json:"legacy_string,omitempty"`
	Number        string `json:"number,omitempty"`  //mandatory
	Summary       string `json:"summary,omitempty"` //mandatory
}

// describe the relation between products (optional)
type productTree struct { //security advisory
	Branches         []branches        `json:"branches,omitempty"`
	FullProductNames []fullProductName `json:"full_product_name,omitempty"`
	ProductGroups    []productGroup    `json:"product_groups,omitempty"`
	Relationships    []relationship    `json:"relationships,omitempty"`
}

type productGroup struct {
	GroupID    string   `json:"group_id,omitempty"`
	ProductIDs []string `json:"product_ids,omitempty"`
	Summary    string   `json:"summary,omitempty"`
}

type relationship struct {
	Category                  string          `json:"category,omitempty"`
	FullProductName           fullProductName `json:"full_product_name,omitempty"`
	ProductReference          string          `json:"product_reference,omitempty"`
	RelatesToProductReference string          `json:"relates_to_product_reference,omitempty"`
}

// describe the vulnerabilities present in products
type vulnerability struct { //security advisory
	Acknowledgements *acknowledgements `json:"acknowledgements,omitempty"`
	CVE              string            `json:"cve,omitempty"`
	CWE              *struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"cwe,omitempty"`
	DiscoveryDate string `json:"discovery_date,omitempty"`
	Flags         []flag `json:"flags,omitempty"`
	IDs           []struct {
		SystemName string `json:"system_name,omitempty"`
		Text       string `json:"text,omitempty"`
	} `json:"ids,omitempty"`
	Involvements  []involvement `json:"involvements,omitempty"`
	Notes         []note        `json:"notes,omitempty"` //security advisory
	ProductStatus productStatus `json:"product_status,omitempty"`
	References    []reference   `json:"references,omitempty"`
	ReleaseDate   string        `json:"release_date,omitempty"`
	Remediations  []struct {
		Category        string   `json:"category,omitempty"`
		Date            string   `json:"date,omitempty"`
		Details         string   `json:"details,omitempty"`
		Entitlements    []string `json:"entitlements,omitempty"`
		GroupIDs        []string `json:"group_ids,omitempty"`
		ProductIDs      string   `json:"product_ids,omitempty"`
		RestartRequired struct {
			Category string `json:"category,omitempty"`
			Details  string `json:"details,omitempty"`
		} `json:"restart_required,omitempty"`
		URL string `json:"url,omitempty"`
	} `json:"remediations,omitempty"`
	Scores []struct {
		CVSSV2   string   `json:"cvss_v2,omitempty"`
		CVSSV3   string   `json:"cvss_v3,omitempty"`
		Products []string `json:"products,omitempty"`
	} `json:"scores,omitempty"`
	Threats []threat `json:"threats,omitempty"`
	Title   string   `json:"title,omitempty"`
}

type flag struct {
	Date       string   `json:"date,omitempty"`
	GroupIDs   []string `json:"group_ids,omitempty"`
	Label      string   `json:"label,omitempty"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

type involvement struct {
	Date    string `json:"date,omitempty"`
	Party   string `json:"party,omitempty"`
	Status  string `json:"status,omitempty"`
	Summary string `json:"summary,omitempty"`
}

type productStatus struct { //security advisory
	FirstAffected      []string `json:"first_affected,omitempty"`
	FirstFixed         []string `json:"first_fixed,omitempty"`
	Fixed              []string `json:"fixed,omitempty"`
	KnownAffected      []string `json:"known_affected,omitempty"`
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	LastAffected       []string `json:"last_affected,omitempty"`
	Recommended        []string `json:"recommended,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

type threat struct {
	Category   string   `json:"category,omitempty"`
	Date       string   `json:"date,omitempty"`
	Details    string   `json:"details,omitempty"`
	GroupIDs   []string `json:"group_ids,omitempty"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

type acknowledgements struct {
	Names        []string `json:"names,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	URLS         []string `json:"urls,omitempty"`
}

type branches struct {
	Branches []branches       `json:"branches,omitempty"`
	Category string           `json:"category,omitempty"`
	Name     string           `json:"name,omitempty"`
	Product  *fullProductName `json:"product,omitempty"`
}

type fullProductName struct {
	Name                        string                       `json:"name,omitempty"`
	ProductID                   string                       `json:"product_id,omitempty"`
	ProductIdentificationHelper *productIdentificationHelper `json:"product_identification_helper,omitempty"`
}

type productIdentificationHelper struct {
	CPE    string `json:"cpe,omitempty"`
	Hashes []struct {
		FileHashes []struct {
			Algorithm string `json:"algorithm,omitempty"`
			Value     string `json:"value,omitempty"`
		} `json:"file_hashes,omitempty"`
		FileName string `json:"filename,omitempty"`
	} `json:"hashes,omitempty"`
	ModelNumbers []string `json:"model_numbers,omitempty"`
	PURL         string   `json:"purl,omitempty"`
	SBOMURLS     []string `json:"sbom_urls,omitempty"`
	SKUS         []string `json:"skus,omitempty"`
	//generic uris...
}

type note struct {
	Audience string `json:"audience,omitempty"`
	Category string `json:"category,omitempty"`
	Text     string `json:"text,omitempty"`
	Title    string `json:"title,omitempty"`
}

type reference struct {
	Category string `json:"category,omitempty"`
	Summary  string `json:"summary,omitempty"`
	URL      string `json:"url,omitempty"`
}

type providerMetadata struct {
	URL                     string                         `json:"canonical_url,omitempty"`
	Distribution            []distributionProviderMetadata `json:"distribution,omitempty"`
	LastUpdated             string                         `json:"last_updated,omitempty"`
	ListOnCSAFAggregators   bool                           `json:"list_on_CSAF_aggregators,omitempty"`
	MetadataVersion         string                         `json:"metadata_version,omitempty"`
	MirrorOnCSAFAggregators bool                           `json:"mirror_on_CSAF_aggregators,omitempty"`
	PublicOpenpgpKeys       []pgpKey                       `json:"public_openpgp_keys,omitempty"`
	Publisher               publisher                      `json:"publisher,omitempty"`
	Role                    string                         `json:"role,omitempty"`
}

type distributionProviderMetadata struct {
	Summary  string `json:"summary"`
	TLPLabel string `json:"tlp_label"`
	URL      string `json:"url"`
}
type aggregator struct {
	AggregatorObject  aggregatorObject `json:"aggregator,omitempty"`
	AggregatorVersion string           `json:"aggregator_version,omitempty"`
	CanonicalURL      string           `json:"canonical_url,omitempty"`
	CsafProviders     []struct {
		Metadata aggregatorMetadata `json:"metadata,omitempty"`
	} `json:"csaf_providers,omitempty"`
	CsafPublishers []struct {
		Metadata       publisherMetadata `json:"csaf_publishers,omitempty"`
		Mirrors        []string          `json:"mirrors,omitempty"`
		UpdateInterval string            `json:"update_interval,omitempty"`
	} `json:"csaf_publishers,omitempty"`
	LastUpdated string `json:"last_updated,omitempty"`
}

type aggregatorObject struct {
	Category         string `json:"category"`
	ContactDetails   string `json:"contact_details"`
	IssuingAuthority string `json:"issuing_authority"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
}

type aggregatorMetadata struct {
	LastUpdated string `json:"last_updated"`
	Publisher   struct {
		Category  string `json:"category"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"publisher"`
	Role string `json:"role"`
	URL  string `json:"url"`
}

type publisherMetadata struct {
	LastUpdated string `json:"last_updated"`
	Publisher   struct {
		Category  string `json:"category"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"publisher"`
	Role string `json:"role"`
	URL  string `json:"url"`
}

type pgpKey struct {
	Fingerprint *string `json:"fingerprint"`
	URL         string  `json:"url"`
}
