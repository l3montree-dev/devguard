package csaf

type csaf_service struct {
}

// root struct of the document
type csaf struct {
	Document        document        `json:"document"`
	ProductTree     productTree     `json:"product_tree"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

// ----------MAJOR CATEGORIES----------
// only mandatory parent category
type document struct {
	Acknowledgements  acknowledgements `json:"acknowledgements"`
	AggregateSeverity struct {
		Namespace string `json:"namespace"`
		Text      string `json:"text"`
	} `json:"aggregate_severity"`
	Category     string `json:"category"`
	CSAFVersion  string `json:"csaf_version"`
	Distribution struct {
		Text string `json:"text"`
		TLP  struct {
			Label string `json:"label"`
			URL   string `json:"url"`
		} `json:"tlp"`
	} `json:"distribution"`
	Language  language `json:"lang"`
	Notes     []note   `json:"notes"`
	Publisher struct {
		Category         string `json:"category"`
		ContactDetails   string `json:"contact_details"`
		IssuingAuthority string `json:"issuing_authority"`
		Name             string `json:"name"`
		Namespace        string `json:"namespace"`
	} `json:"publisher"`
	References     []reference `json:"references"`
	SourceLanguage language    `json:"source_lang"`
	Title          string      `json:"title"`
	Tracking       struct {
		Aliases            []string `json:"aliases"`
		CurrentReleaseDate string   `json:"current_release_date"`
		Generator          struct {
			Date   string `json:"date"`
			Engine struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"engine"`
		} `json:"generator"`
		ID                 string `json:"id"`
		InitialReleaseDate string `json:"initial_release_date"`
		RevisionHistory    []struct {
			Date          string `json:"date"`
			LegacyVersion string `json:"legacy_version"`
			Number        version
			Summary       string `json:"summary"`
		} `json:"revision_history"`
		Status  string  `json:"status"`
		Version version `json:"version"`
	} `json:"tracking"`
}

// describe the relation between products (optional)
type productTree struct {
	Branches         branches          `json:"branches"`
	FullProductNames []fullProductName `json:"full_product_name"`
	ProductGroups    []struct {
		GroupID    productGroupID `json:"group_id"`
		ProductIDs []productID    `json:"product_ids"`
		Summary    string         `json:"summary"`
	} `json:"product_groups"`
	Relationships struct {
		Category                  string          `json:"category"`
		FullProductName           fullProductName `json:"full_product_name"`
		ProductReference          productID       `json:"product_reference"`
		RelatesToProductReference productID       `json:"relates_to_product_reference"`
	} `json:"relationships"`
}

// describe the vulnerabilities present in products
type vulnerability struct {
	Acknowledgements acknowledgements `json:"acknowledgements"`
	CVE              string           `json:"cve"`
	CWE              struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"cwe"`
	DiscoveryDate string `json:"discovery_date"`
	Flags         []struct {
		Date       string         `json:"date"`
		GroupIDs   []productGroup `json:"group_ids"`
		Label      string         `json:"label"`
		ProductIDs products       `json:"product_ids"`
	} `json:"flags"`
	IDs []struct {
		SystemName string `json:"system_name"`
		Text       string `json:"text"`
	} `json:"ids"`
	Involvements []struct {
		Date    string `json:"date"`
		Party   string `json:"party"`
		Status  string `json:"status"`
		Summary string `json:"summary"`
	} `json:"involvements"`
	Notes         []note `json:"notes"`
	ProductStatus struct {
		FirstAffected      products `json:"first_affected"`
		FirstFixed         products `json:"first_fixed"`
		Fixed              products `json:"fixed"`
		KnownAffected      products `json:"known_affected"`
		KnownNotAffected   products `json:"known_not_affected"`
		LastAffected       products `json:"last_affected"`
		Recommended        products `json:"recommended"`
		UnderInvestigation products `json:"under_investigation"`
	} `json:"product_status"`
	References  []reference `json:"references"`
	ReleaseDate string      `json:"release_date"`
	Remediatons []struct {
		Category        string         `json:"category"`
		Date            string         `json:"date"`
		Details         string         `json:"details"`
		Entitlements    []string       `json:"entitlements"`
		GroupIDs        []productGroup `json:"group_ids"`
		ProductIDs      products       `json:"product_ids"`
		RestartRequired struct {
			Category string `json:"category"`
			Details  string `json:"details"`
		} `json:"restart_required"`
		URL string `json:"url"`
	} `json:"remediatons"`
	Scores []struct {
		CVSSV2   string   `json:"cvss_v2"`
		CVSSV3   string   `json:"cvss_v3"`
		Products products `json:"products"`
	} `json:"scores"`
	Threats []struct {
		Category   string         `json:"category"`
		Date       string         `json:"date"`
		Details    string         `json:"details"`
		GroupIDs   []productGroup `json:"group_ids"`
		ProductIDs products       `json:"product_ids"`
	} `json:"threats"`
	Title string `json:"title"`
}

// ----------TYPE DEFINITIONS----------
type acknowledgements struct {
	Names        []string `json:"names"`
	Organization string   `json:"organization"`
	Summary      string   `json:"summary"`
	URLS         []string `json:"urls"`
}

type branches struct {
	Branches []branches      `json:"branches"`
	Category string          `json:"category"`
	Name     string          `json:"name"`
	Product  fullProductName `json:"product"`
}

type fullProductName struct {
	Name                        string                      `json:"name"`
	ProductID                   productID                   `json:"product_id"`
	ProductIdentificationHelper productIdentificationHelper `json:"product_identification_helper"`
}

type productIdentificationHelper struct {
	CPE    string `json:"cpe"`
	Hashes []struct {
		FileHashes []struct {
			Algorithm string `json:"algorithm"`
			Value     string `json:"value"`
		} `json:"file_hashes"`
		FileName string `json:"filename"`
	} `json:"hashes"`
	ModelNumbers []string `json:"model_numbers"`
	PURL         string   `json:"purl"`
	SBOMURLS     []string `json:"sbom_urls"`
	SKUS         []string `json:"skus"`
	//generic uris...
}

type language = string

type note struct {
	Audience string `json:"audience"`
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title"`
}

type productGroupID = string

type productGroup = []productGroupID

type products = []productID

type reference struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

type version = string

type productID = string

func NewCSAFService() *csaf_service {
	return &csaf_service{}
}

func (*csaf_service) generateCSAFReport() error {

	return nil
}
