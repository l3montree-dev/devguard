package csaf

import (
	"encoding/json"
	"os"

	"github.com/l3montree-dev/devguard/internal/core"
)

type csaf_controller struct {
	DB core.DB
}

// root struct of the document
type csaf struct {
	Document        document        `json:"document,omitempty"`
	ProductTree     productTree     `json:"product_tree,omitempty"`
	Vulnerabilities []vulnerability `json:"vulnerabilities,omitempty"`
}

// ----------MAJOR CATEGORIES----------
// only mandatory parent category
type document struct {
	Acknowledgements  acknowledgements `json:"acknowledgements,omitempty"`
	AggregateSeverity struct {
		Namespace string `json:"namespace,omitempty"`
		Text      string `json:"text,omitempty"`
	} `json:"aggregate_severity,omitempty"`
	Category     string `json:"category,omitempty"`     //mandatory
	CSAFVersion  string `json:"csaf_version,omitempty"` //mandatory
	Distribution struct {
		Text string `json:"text,omitempty"`
		TLP  struct {
			Label string `json:"label,omitempty"`
			URL   string `json:"url,omitempty"`
		} `json:"tlp,omitempty"`
	} `json:"distribution,omitempty"`
	Language       language             `json:"lang,omitempty"`
	Notes          []note               `json:"notes,omitempty"`
	Publisher      publisherReplacement `json:"publisher,omitempty"`
	References     []reference          `json:"references,omitempty"`
	SourceLanguage language             `json:"source_lang,omitempty"`
	Title          string               `json:"title,omitempty"` //mandatory
	Tracking       struct {
		Aliases            []string `json:"aliases,omitempty"`
		CurrentReleaseDate string   `json:"current_release_date,omitempty"` //mandatory
		Generator          struct {
			Date   string `json:"date,omitempty"`
			Engine struct {
				Name    string `json:"name,omitempty"`
				Version string `json:"version,omitempty"`
			} `json:"engine,omitempty"`
		} `json:"generator,omitempty"`
		ID                 string                `json:"id,omitempty"`                   //mandatory
		InitialReleaseDate string                `json:"initial_release_date,omitempty"` //mandatory
		RevisionHistory    []revisionReplacement `json:"revision_history,omitempty"`
		Status             string                `json:"status,omitempty"`  //mandatory
		Version            version               `json:"version,omitempty"` //mandatory
	} `json:"tracking,omitempty"`
}

type publisherReplacement struct {
	Category         string `json:"category,omitempty"` //mandatory
	ContactDetails   string `json:"contact_details,omitempty"`
	IssuingAuthority string `json:"issuing_authority,omitempty"`
	Name             string `json:"name,omitempty"`      //mandatory
	Namespace        string `json:"namespace,omitempty"` //mandatory
}

type revisionReplacement struct {
	Date          string  `json:"date,omitempty"` //mandatory
	LegacyVersion string  `json:"legacy_version,omitempty"`
	Number        version //mandatory
	Summary       string  `json:"summary,omitempty"` //mandatory
}

// describe the relation between products (optional)
type productTree struct { //security advisory
	Branches         branches                  `json:"branches,omitempty"`
	FullProductNames []fullProductName         `json:"full_product_name,omitempty"`
	ProductGroups    []productGroupReplacement `json:"product_groups,omitempty"`
	Relationships    []relationshipReplacement `json:"relationships,omitempty"`
}

type productGroupReplacement struct {
	GroupID    productGroupID `json:"group_id,omitempty"`
	ProductIDs []productID    `json:"product_ids,omitempty"`
	Summary    string         `json:"summary,omitempty"`
}

type relationshipReplacement struct {
	Category                  string          `json:"category,omitempty"`
	FullProductName           fullProductName `json:"full_product_name,omitempty"`
	ProductReference          productID       `json:"product_reference,omitempty"`
	RelatesToProductReference productID       `json:"relates_to_product_reference,omitempty"`
}

// describe the vulnerabilities present in products
type vulnerability struct { //security advisory
	Acknowledgements acknowledgements `json:"acknowledgements,omitempty"`
	CVE              string           `json:"cve,omitempty"`
	CWE              struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"cwe,omitempty"`
	DiscoveryDate string            `json:"discovery_date,omitempty"`
	Flags         []flagReplacement `json:"flags,omitempty"`
	IDs           []struct {
		SystemName string `json:"system_name,omitempty"`
		Text       string `json:"text,omitempty"`
	} `json:"ids,omitempty"`
	Involvements  []involvementReplacement `json:"involvements,omitempty"`
	Notes         []note                   `json:"notes,omitempty"` //security advisory
	ProductStatus productStatusReplacement `json:"product_status,omitempty"`
	References    []reference              `json:"references,omitempty"`
	ReleaseDate   string                   `json:"release_date,omitempty"`
	Remediatons   []struct {
		Category        string         `json:"category,omitempty"`
		Date            string         `json:"date,omitempty"`
		Details         string         `json:"details,omitempty"`
		Entitlements    []string       `json:"entitlements,omitempty"`
		GroupIDs        []productGroup `json:"group_ids,omitempty"`
		ProductIDs      products       `json:"product_ids,omitempty"`
		RestartRequired struct {
			Category string `json:"category,omitempty"`
			Details  string `json:"details,omitempty"`
		} `json:"restart_required,omitempty"`
		URL string `json:"url,omitempty"`
	} `json:"remediatons,omitempty"`
	Scores []struct {
		CVSSV2   string   `json:"cvss_v2,omitempty"`
		CVSSV3   string   `json:"cvss_v3,omitempty"`
		Products products `json:"products,omitempty"`
	} `json:"scores,omitempty"`
	Threats []threatReplacement `json:"threats,omitempty"`
	Title   string              `json:"title,omitempty"`
}

type flagReplacement struct {
	Date       string         `json:"date,omitempty"`
	GroupIDs   []productGroup `json:"group_ids,omitempty"`
	Label      string         `json:"label,omitempty"`
	ProductIDs products       `json:"product_ids,omitempty"`
}

type involvementReplacement struct {
	Date    string `json:"date,omitempty"`
	Party   string `json:"party,omitempty"`
	Status  string `json:"status,omitempty"`
	Summary string `json:"summary,omitempty"`
}

type productStatusReplacement struct { //security advisory
	FirstAffected      products `json:"first_affected,omitempty"`
	FirstFixed         products `json:"first_fixed,omitempty"`
	Fixed              products `json:"fixed,omitempty"`
	KnownAffected      products `json:"known_affected,omitempty"`
	KnownNotAffected   products `json:"known_not_affected,omitempty"`
	LastAffected       products `json:"last_affected,omitempty"`
	Recommended        products `json:"recommended,omitempty"`
	UnderInvestigation products `json:"under_investigation,omitempty"`
}

type threatReplacement struct {
	Category   string         `json:"category,omitempty"`
	Date       string         `json:"date,omitempty"`
	Details    string         `json:"details,omitempty"`
	GroupIDs   []productGroup `json:"group_ids,omitempty"`
	ProductIDs products       `json:"product_ids,omitempty"`
}

// ----------TYPE DEFINITIONS----------
type acknowledgements struct {
	Names        []string `json:"names,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	URLS         []string `json:"urls,omitempty"`
}

type branches struct {
	Branches []branches      `json:"branches,omitempty"`
	Category string          `json:"category,omitempty"`
	Name     string          `json:"name,omitempty"`
	Product  fullProductName `json:"product,omitempty"`
}

type fullProductName struct {
	Name                        string                      `json:"name,omitempty"`
	ProductID                   productID                   `json:"product_id,omitempty"`
	ProductIdentificationHelper productIdentificationHelper `json:"product_identification_helper,omitempty"`
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

type language = string

type note struct {
	Audience string `json:"audience,omitempty"`
	Category string `json:"category,omitempty"`
	Text     string `json:"text,omitempty"`
	Title    string `json:"title,omitempty"`
}

type productGroupID = string

type productGroup = []productGroupID

type products = []productID

type reference struct {
	Category string `json:"category,omitempty"`
	Summary  string `json:"summary,omitempty"`
	URL      string `json:"url,omitempty"`
}

type version = string

type productID = string

func NewCSAFCollector(db core.DB) *csaf_controller {
	return &csaf_controller{
		DB: db,
	}
}

func (*csaf_controller) GenerateCSAFReport(ctx core.Context) error {
	fd, err := os.Create("csaf.json")
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(fd)
	document, err := generateDocumentValues(ctx)
	if err != nil {
		return err
	}
	err = encoder.Encode(document)
	if err != nil {
		return err
	}

	return nil
}

func generateDocumentValues(ctx core.Context) (document, error) {
	var document document
	org := core.GetOrg(ctx)

	document.Category = "csaf_security_advisory"
	document.CSAFVersion = "2.0"
	document.Publisher = publisherReplacement{
		Category:  "vendor",
		Name:      org.Slug,
		Namespace: "", //TODO
	}
	document.Title = "csaf_v1"
	return document, nil
}
