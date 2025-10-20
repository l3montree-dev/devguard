package csaf

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	pgpCrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
)

// definition of all necessary structs used in a csaf document

type csafController struct {
	DependencyVulnRepository core.DependencyVulnRepository
	VulnEventRepository      core.VulnEventRepository
	AssetVersionRepository   core.AssetVersionRepository
	statisticsRepository     core.StatisticsRepository
}

// root struct of the document
type csaf struct {
	Document        documentObject  `json:"document"`
	ProductTree     *productTree    `json:"product_tree,omitempty"`
	Vulnerabilities []vulnerability `json:"vulnerabilities,omitempty"`
}

// ----------MAJOR CATEGORIES----------
// only mandatory parent category
type documentObject struct {
	Acknowledgements  *acknowledgements `json:"acknowledgements,omitempty"`
	AggregateSeverity *struct {
		Namespace string `json:"namespace,omitempty"`
		Text      string `json:"text,omitempty"`
	} `json:"aggregate_severity,omitempty"`
	Category       string                   `json:"category,omitempty"`     //mandatory
	CSAFVersion    string                   `json:"csaf_version,omitempty"` //mandatory
	Distribution   *distributionReplacement `json:"distribution,omitempty"`
	Language       *language                `json:"lang,omitempty"`
	Notes          []note                   `json:"notes,omitempty"`
	Publisher      publisherReplacement     `json:"publisher,omitempty"` //mandatory
	References     []reference              `json:"references,omitempty"`
	SourceLanguage *language                `json:"source_lang,omitempty"`
	Title          string                   `json:"title,omitempty"`    //mandatory
	Tracking       trackingObject           `json:"tracking,omitempty"` //mandatory
}

type trackingObject struct {
	Aliases            []string `json:"aliases,omitempty"`
	CurrentReleaseDate string   `json:"current_release_date,omitempty"` //mandatory
	Generator          *struct {
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
}

type distributionReplacement struct {
	Text string `json:"text,omitempty"`
	TLP  struct {
		Label string `json:"label,omitempty"`
		URL   string `json:"url,omitempty"`
	} `json:"tlp,omitempty"`
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
	Number        version `json:"number,omitempty"`  //mandatory
	Summary       string  `json:"summary,omitempty"` //mandatory
}

// describe the relation between products (optional)
type productTree struct { //security advisory
	Branches         []branches                `json:"branches,omitempty"`
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
	Acknowledgements *acknowledgements `json:"acknowledgements,omitempty"`
	CVE              string            `json:"cve,omitempty"`
	CWE              *struct {
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
	Remediations  []struct {
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
	} `json:"remediations,omitempty"`
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
	Branches []branches       `json:"branches,omitempty"`
	Category string           `json:"category,omitempty"`
	Name     string           `json:"name,omitempty"`
	Product  *fullProductName `json:"product,omitempty"`
}

type fullProductName struct {
	Name                        string                       `json:"name,omitempty"`
	ProductID                   productID                    `json:"product_id,omitempty"`
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

// from here on: code that builds the human navigable html web interface

func NewCSAFController(dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository, assetVersionRepository core.AssetVersionRepository, statisticsRepository core.StatisticsRepository) *csafController {
	return &csafController{
		DependencyVulnRepository: dependencyVulnRepository,
		VulnEventRepository:      vulnEventRepository,
		AssetVersionRepository:   assetVersionRepository,
		statisticsRepository:     statisticsRepository,
	}
}

// signs data and returns the resulting signature
func signCSAFReport(csafJSON []byte) ([]byte, error) {
	// configure pgp profile to meet the csaf standard
	pgp := pgpCrypto.PGPWithProfile(profile.RFC4880())

	// read private key and parse to opnepgp key struct
	privateKeyData, err := os.ReadFile("csaf-openpgp-private-key.asc")
	if err != nil {
		return nil, err
	}
	privateKeyArmored := string(privateKeyData)
	privateKey, err := pgpCrypto.NewKeyFromArmored(privateKeyArmored)
	if err != nil {
		return nil, err
	}

	// unlock private key using the passphrase
	password := os.Getenv("CSAF_PASSPHRASE")
	if password == "" {
		return nil, fmt.Errorf("could not read csaf passphrase from environment variables, check your CSAF_PASSPHRASE variable in your .env file")
	}
	unlockedKey, err := privateKey.Unlock([]byte(password))
	if err != nil {
		return nil, err
	}

	// sign the document and return signature
	signer, err := pgp.Sign().SigningKey(unlockedKey).Detached().New()
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(csafJSON, pgpCrypto.Armor)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// builds and returns the index.txt file, listing all csaf reports currently available
func (controller *csafController) GetIndexFile(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	// build revision history first
	tracking, err := generateTrackingObject(asset, controller.DependencyVulnRepository, controller.VulnEventRepository, int(^uint(0)>>1))
	if err != nil {
		return err
	}

	// then write each revision entry version to the index string
	index := ""
	for _, entry := range tracking.RevisionHistory {
		year := entry.Date[:4]
		fileName := fmt.Sprintf("csaf_report_%s_%s.json", strings.ToLower(asset.Slug), strings.ToLower(entry.Number))
		index += fmt.Sprintf("%s/%s\n", year, fileName)
	}
	return ctx.String(200, index)
}

// builds and returns the changes.csv file, containing all reports ordered by release dates
func (controller *csafController) GetChangesCSVFile(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	// build revision history first
	tracking, err := generateTrackingObject(asset, controller.DependencyVulnRepository, controller.VulnEventRepository, int(^uint(0)>>1))
	if err != nil {
		return err
	}

	// sort resulting revision history by date in descending order
	slices.SortFunc(tracking.RevisionHistory, func(revision1, revision2 revisionReplacement) int {
		time1, _ := time.Parse(time.RFC3339, revision1.Date) //nolint:all
		time2, _ := time.Parse(time.RFC3339, revision2.Date) //nolint:all
		return time1.Compare(time2) * -1
	})

	// then write each entry to the csv string and return the result
	csvContents := ""
	for _, entry := range tracking.RevisionHistory {
		year := entry.Date[:4]
		fileName := fmt.Sprintf("csaf_report_%s_%s.json", strings.ToLower(asset.Slug), strings.ToLower(entry.Number))
		csvContents += fmt.Sprintf("\"%s/%s\",\"%s\"\n", year, fileName, entry.Date)
	}

	return ctx.String(200, csvContents)
}

// returns the html to display each subdirectory present under the csaf url
func (controller *csafController) GetCSAFIndexHTML(ctx core.Context) error {
	html := `<html>
	<head><title>Index of /csaf/</title></head>
	<body cz-shortcut-listen="true">
	<h1>Index of /csaf/</h1><hr><pre>
	<a href="openpgp/">openpgp/</a>
	<a href="white/">white/</a>
	<a href="provider-metadata.json" download="provider-metadata.json">provider-metadata.json</a>
	</pre><hr>
	</body>
	</html>`
	return ctx.HTML(200, html)
}

// return the html used to display all openpgp related keys and hashes
func (controller *csafController) GetOpenPGPHTML(ctx core.Context) error {
	fingerprint, err := getPublicKeyFingerprint()
	if err != nil {
		return err
	}

	html := fmt.Sprintf(`<html>
	<head><title>Index of /csaf/openpgp/</title></head>
	<body cz-shortcut-listen="true">
	<h1>Index of /csaf/openpgp</h1><hr><pre>
	<a href="../">../</a>
	<a href="%s.asc" download="%s.asc">%s.asc</a>
	<a href="%s.asc.sha512" download="%s.asc.sha512">%s.asc.sha512</a>
	</pre><hr>
	</body>
	</html>`, fingerprint, fingerprint, fingerprint, fingerprint, fingerprint, fingerprint)
	return ctx.HTML(200, html)
}

// returns the set of all years where new csaf versions where published
func getAllYears(asset models.Asset, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository) ([]int, error) {
	vulns, err := dependencyVulnRepository.GetAllVulnsByAssetID(nil, asset.ID)
	if err != nil {
		return nil, err
	}

	// iterate over every event = version, check the release year and append if not already present
	allYears := make([]int, 0)
	for _, vuln := range vulns {
		events, err := vulnEventRepository.GetSecurityRelevantEventsForVulnID(nil, vuln.ID)
		if err != nil {
			return nil, err
		}
		for _, event := range events {
			if !slices.Contains(allYears, event.CreatedAt.Year()) {
				allYears = append(allYears, event.CreatedAt.Year())
			}
		}
	}

	slices.Sort(allYears)
	return allYears, nil
}

// builds and returns the html used to display every directory in the tlp white folder
func (controller *csafController) GetTLPWhiteEntriesHTML(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	// get all years where csaf version were published and make a directory for each of these
	allYears, err := getAllYears(asset, controller.DependencyVulnRepository, controller.VulnEventRepository)
	if err != nil {
		return err
	}
	html := `<html>
	<head><title>Index of /csaf/white/</title></head>
	<body cz-shortcut-listen="true">
	<h1>Index of /csaf/white/</h1><hr><pre>`
	html += "\n"
	html += `	<a href="../">../</a>`

	for _, year := range allYears {
		html += "\n"
		html += fmt.Sprintf(`	<a href="%d/">%d/</a>`, year, year)
	}

	// then append the index.txt as well as the changes.csv file
	html += "\n"
	html += `	<a href="index.txt/" download="index.txt">index.txt</a>`

	html += "\n"
	html += `	<a href="changes.csv/" download="changes.csv">changes.csv</a>`

	html += `</pre><hr>
	</body>
		</html>`

	return ctx.HTML(200, html)
}

// builds and returns the html to display every csaf version of a given year as well as the signature and hash
func (controller *csafController) GetReportsByYearHTML(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	// extract the requested year and build the revision history first
	year := strings.TrimRight(ctx.Param("year"), "/")
	tracking, err := generateTrackingObject(asset, controller.DependencyVulnRepository, controller.VulnEventRepository, int(^uint(0)>>1))
	if err != nil {
		return err
	}

	// then filter each csaf version if they are released in the given year
	entriesForYear := make([]revisionReplacement, 0)
	yearNumber, err := strconv.Atoi(year)
	if err != nil {
		return err
	}

	for _, entry := range tracking.RevisionHistory {
		date, err := time.Parse(time.RFC3339, entry.Date)
		if err != nil {
			return err
		}
		if date.Year() == yearNumber {
			entriesForYear = append(entriesForYear, entry)
		}
	}

	// finally generate the html for each version as well as the signature and hash
	html := fmt.Sprintf(`<html>
	<head><title>Index of /csaf/white/%s/</title></head>
	<body cz-shortcut-listen="true">
	<h1>Index of /csaf/white/%s/</h1><hr><pre>`, year, year)
	html += "\n"
	html += `	<a href="../">../</a>`

	for _, entry := range entriesForYear {
		fileName := fmt.Sprintf("csaf_report_%s_%s.json", strings.ToLower(asset.Slug), strings.ToLower(entry.Number))
		html += fmt.Sprintf(`
	<a href="%s" download="%s">%s</a>
	<a href="%s.asc" download="%s.asc">%s.asc</a>
	<a href="%s.sha512" download="%s.sha512">%s.sha512</a>`, fileName, fileName, fileName, fileName, fileName, fileName, fileName, fileName, fileName)
	}
	html += `</pre><hr>
	</body>
		</html>`
	return ctx.HTML(200, html)
}

// handles request to files placed in the openpgp directory (currently public key and the respective sha512 hash)
func (controller *csafController) GetOpenPGPFile(ctx core.Context) error {
	// determine which type of file is requested
	file := ctx.Param("file")
	file = strings.TrimSuffix(file, "/")
	index := strings.LastIndex(file, ".")
	if index == -1 {
		return fmt.Errorf("invalid resource: %s", file)
	}
	extension := file[index:] //get the file extension
	if extension != ".asc" && extension != ".sha512" {
		return fmt.Errorf("invalid resource: %s", file)
	}

	publicKeyData, err := os.ReadFile("csaf-openpgp-public-key.asc")
	if err != nil {
		return err
	}
	switch extension {
	case ".asc":
		// just return the public key
		return ctx.String(200, string(publicKeyData))
	case ".sha512":
		// else hash the public key and return the result
		hash := sha512.Sum512(publicKeyData)
		hashString := hex.EncodeToString(hash[:])
		return ctx.String(200, hashString)
	}
	return fmt.Errorf("invalid resource: %s", file)
}

type ProviderMetadata struct {
	URL                     string               `json:"canonical_url"`
	LastUpdated             string               `json:"last_updated"`
	ListOnCSAFAggregators   bool                 `json:"list_on_CSAF_aggregators"`
	MetadataVersion         string               `json:"metadata_version"`
	MirrorOnCSAFAggregators bool                 `json:"mirror_on_CSAF_aggregators"`
	PublicOpenpgpKeys       []PGPKey             `json:"public_openpgp_keys"`
	Publisher               publisherReplacement `json:"publisher"`
	Role                    string               `json:"role"`
}

type PGPKey struct {
	Fingerprint *string `json:"fingerprint"`
	URL         string  `json:"url"`
}

// returns the provider metadata file
func (controller *csafController) GetProviderMetadata(ctx core.Context) error {
	organization := core.GetOrg(ctx)
	project := core.GetProject(ctx)
	asset := core.GetAsset(ctx)
	hostURL := os.Getenv("API_URL")
	if hostURL == "" {
		return fmt.Errorf("could not get api url from environment variables, check the API_URL variable in the .env file")
	}
	csafURL := fmt.Sprintf("%s/api/v1/organizations/%s/projects/%s/assets/%s/csaf/", hostURL, organization.Slug, project.Slug, asset.Slug)

	fingerprint, err := getPublicKeyFingerprint()
	if err != nil {
		return err
	}

	metadata := ProviderMetadata{
		URL:                     csafURL + "provider-metadata.json",
		LastUpdated:             time.Now().Format(time.RFC3339),
		ListOnCSAFAggregators:   true,
		MirrorOnCSAFAggregators: true,
		Role:                    "csaf_trusted_provider",
		MetadataVersion:         "2.0",
		Publisher: publisherReplacement{
			Category:       "vendor",
			ContactDetails: "info@l3montree.com",
			Name:           "L3montree GmbH",
			Namespace:      "https://l3montree.com/",
		},
		PublicOpenpgpKeys: []PGPKey{{Fingerprint: &fingerprint, URL: csafURL + "openpgp/" + fingerprint + ".asc"}},
	}

	return ctx.JSONPretty(200, metadata, "    ")
}

func getPublicKeyFingerprint() (string, error) {
	publicKeyMaterial, err := os.ReadFile("csaf-openpgp-public-key.asc")
	if err != nil {
		return "", err
	}
	hash := sha1.Sum(publicKeyMaterial)
	hashString := hex.EncodeToString(hash[:])
	return hashString, nil
}

// from here on: code that handles the creation of csaf reports them self

// handles all requests directed at a specific csaf report version, including the csaf report itself as well as the respective hash and signature
func (controller *csafController) ServeCSAFReportRequest(ctx core.Context) error {
	// generate the report first
	csafReport, err := generateCSAFReport(ctx, controller.DependencyVulnRepository, controller.VulnEventRepository, controller.statisticsRepository, controller.AssetVersionRepository)
	if err != nil {
		return err
	}

	// then choose which type of requested needs to be served
	fileName := strings.TrimRight(ctx.Param("version"), "/")
	index := strings.LastIndex(fileName, ".")
	if index == -1 {
		return fmt.Errorf("invalid file name syntax")
	}
	mode := fileName[index+1:]
	switch mode {
	case "json":
		// just return the csaf report
		return ctx.JSONPretty(200, csafReport, "    ")
	case "asc":
		// return the signature of the json encoding of the report
		buf := bytes.Buffer{}
		encoder := json.NewEncoder(&buf)
		err = encoder.Encode(csafReport)
		if err != nil {
			return err
		}
		signature, err := signCSAFReport(buf.Bytes())
		if err != nil {
			return err
		}
		return ctx.String(200, string(signature))
	case "sha512":
		// return the hash of the report
		buf := bytes.Buffer{}
		encoder := json.NewEncoder(&buf)
		err = encoder.Encode(csafReport)
		if err != nil {
			return err
		}
		hash := sha512.Sum512(buf.Bytes())
		hashString := hex.EncodeToString(hash[:])
		return ctx.String(200, hashString)
	default:
		return fmt.Errorf("invalid file extension")
	}
}

// generate a specific csaf report version
func generateCSAFReport(ctx core.Context, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository, statisticsRepository core.StatisticsRepository, assetVersionRepository core.AssetVersionRepository) (csaf, error) {
	csafDoc := csaf{}
	// extract context information
	version, err := extractVersionFromDocumentID(ctx.Param("version"))
	if err != nil {
		return csafDoc, err
	}
	org := core.GetOrg(ctx)
	asset := core.GetAsset(ctx)

	// build trivial parts of the document field
	csafDoc.Document = documentObject{
		CSAFVersion: "2.0",
		Publisher: publisherReplacement{
			Category:  "vendor",
			Name:      org.Slug,
			Namespace: "https://devguard.org",
		},
		Title:    fmt.Sprintf("Vulnerability history of asset: %s", asset.Slug),
		Language: utils.Ptr("en-US"),
	}

	// TODO change tlp based off of visibility of csaf report, white for public and TLP:AMBER or TLP:RED for access protected reports
	csafDoc.Document.Distribution = &distributionReplacement{
		TLP: struct {
			Label string `json:"label,omitempty"`
			URL   string `json:"url,omitempty"`
		}{
			Label: "WHITE",
			URL:   "https://first.org/tlp",
		},
	}

	tracking, err := generateTrackingObject(asset, dependencyVulnRepository, vulnEventRepository, version)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.Document.Tracking = tracking

	tree, err := generateProductTree(asset, assetVersionRepository)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.ProductTree = &tree

	// get the timestamp of the last revision which we need to time travel to
	lastRevisionTimestamp, err := time.Parse(time.RFC3339, tracking.RevisionHistory[len(tracking.RevisionHistory)-1].Date)
	if err != nil {
		return csafDoc, err
	}
	vulnerabilities, err := generateVulnerabilitiesObject(asset, lastRevisionTimestamp, dependencyVulnRepository, vulnEventRepository, statisticsRepository)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.Vulnerabilities = vulnerabilities

	// if we do not have any vulnerabilities we do not comply with the security framework anymore so we need to switch the category to the base profile
	if len(vulnerabilities) == 0 {
		csafDoc.Document.Category = "csaf_base"
	} else {
		csafDoc.Document.Category = "csaf_security_advisory"
	}

	csafDoc.Document.Tracking.CurrentReleaseDate = csafDoc.Document.Tracking.RevisionHistory[len(csafDoc.Document.Tracking.RevisionHistory)-1].Date

	return csafDoc, nil
}

// generates the product tree object for a specific asset, which includes the default branch as well as all tags
func generateProductTree(asset models.Asset, assetVersionRepository core.AssetVersionRepository) (productTree, error) {
	tree := productTree{}
	assetVersions, err := assetVersionRepository.GetAllTagsAndDefaultBranchForAsset(nil, asset.ID)
	if err != nil {
		return tree, err
	}

	// append each relevant asset version
	for _, version := range assetVersions {
		branch := branches{
			Category: "product_version",
			Name:     version.Name,
			Product: &fullProductName{
				Name:      version.Name,
				ProductID: version.Name,
			},
		}
		tree.Branches = append(tree.Branches, branch)
	}

	return tree, nil
}

// generates the vulnerability object for a specific asset at a certain timeStamp in time
func generateVulnerabilitiesObject(asset models.Asset, timeStamp time.Time, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository, statisticsRepository core.StatisticsRepository) ([]vulnerability, error) {
	vulnerabilites := []vulnerability{}
	timeStamp = convertTimeToDateHourMinute(timeStamp)
	// first get all vulns
	vulns, err := dependencyVulnRepository.GetAllVulnsForTagsAndDefaultBranchInAsset(nil, asset.ID, []models.VulnState{models.VulnStateFixed})
	if err != nil {
		return nil, err
	}
	filteredVulns := make([]models.DependencyVuln, 0, len(vulns))
	for _, vuln := range vulns {
		if vuln.CreatedAt.Before(timeStamp) {
			filteredVulns = append(filteredVulns, vuln)
		}
	}
	if len(filteredVulns) == 0 {
		return vulnerabilites, nil
	}

	// then time travel each vuln to the state at timeStamp using the latest events
	for i, vuln := range filteredVulns {
		lastEvent, err := vulnEventRepository.GetLastEventBeforeTimestamp(nil, vuln.ID, timeStamp)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				//this vulnerability did not exist before this timestamp
				continue
			}
			return nil, err
		}
		lastEvent.Apply(&filteredVulns[i])
	}

	// maps a cve ID to a set of asset versions where it is present to reduce clutter
	cveGroups := make(map[string][]models.DependencyVuln)
	for _, vuln := range filteredVulns {
		cveGroups[*vuln.CVEID] = append(cveGroups[*vuln.CVEID], vuln)
	}

	// then make a vulnerability object for every cve and list the asset version in the product status property
	for cve, vulnsInGroup := range cveGroups {
		vulnObject := vulnerability{
			CVE:   cve,
			Title: cve,
		}
		uniqueVersionsAffected := make([]string, 0, len(vulnsInGroup))
		for _, vuln := range vulnsInGroup {
			// determine the discovery date
			if vulnObject.DiscoveryDate == "" {
				vulnObject.DiscoveryDate = vulnsInGroup[0].CreatedAt.Format(time.RFC3339)
			} else {
				currentDiscoveryDate, err := time.Parse(vulnObject.DiscoveryDate, time.RFC3339)
				if err == nil {
					if currentDiscoveryDate.After(vuln.CreatedAt) {
						vulnObject.DiscoveryDate = vuln.CreatedAt.Format(time.RFC3339)
					}
				}
			}

			if !slices.Contains(uniqueVersionsAffected, vuln.AssetVersionName) {
				uniqueVersionsAffected = append(uniqueVersionsAffected, vuln.AssetVersionName)
			}
		}
		vulnObject.ProductStatus = productStatusReplacement{
			KnownAffected: uniqueVersionsAffected,
		}

		vulnObject.Notes = generateNoteForVulnerabilityObject(vulnsInGroup)
		vulnerabilites = append(vulnerabilites, vulnObject)
	}

	slices.SortFunc(vulnerabilites, func(vuln1, vuln2 vulnerability) int {
		return -strings.Compare(vuln1.CVE, vuln2.CVE)
	})
	return vulnerabilites, nil
}

// generate the textual summary for a vulnerability object
func generateNoteForVulnerabilityObject(vulns []models.DependencyVuln) []note {
	vulnDetails := note{
		Category: "details",
		Title:    "state of the vulnerability in the product",
	}

	// for each vuln in this object list the respective purl and the current state
	summary := ""
	versionsToVulns := make(map[string][]models.DependencyVuln, len(vulns))
	for _, vuln := range vulns {
		versionsToVulns[vuln.AssetVersionName] = append(versionsToVulns[vuln.AssetVersionName], vuln)
	}
	for version, versionVulns := range versionsToVulns {
		summary += fmt.Sprintf("Version %s: ", version)
		for _, vuln := range versionVulns {
			switch vuln.State {
			case models.VulnStateOpen:
				summary += "unhandled for purl " + *vuln.ComponentPurl + ", "
			case models.VulnStateAccepted:
				summary += "accepted for purl " + *vuln.ComponentPurl + ", "
			case models.VulnStateFalsePositive:
				summary += "marked as false positive for purl " + *vuln.ComponentPurl + ", "
			}
		}
		summary = strings.TrimRight(summary, ", ")
		summary += "| "
	}
	summary = strings.TrimRight(summary, "| ")
	vulnDetails.Text = summary
	return []note{vulnDetails}
}

// generate the tracking object used by the document object
func generateTrackingObject(asset models.Asset, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository, documentVersion int) (trackingObject, error) {
	tracking := trackingObject{}
	// first get all dependency vulns for an asset
	vulns, err := dependencyVulnRepository.GetAllVulnsByAssetID(nil, asset.ID)
	if err != nil {
		return tracking, err
	}

	// then collect all security relevant events
	allEvents := make([]models.VulnEvent, 0, len(vulns))
	for _, vuln := range vulns {
		events, err := vulnEventRepository.GetSecurityRelevantEventsForVulnID(nil, vuln.ID)
		if err != nil {
			return tracking, err
		}
		allEvents = append(allEvents, events...)
	}

	// sort them by their creation timestamp
	slices.SortFunc(allEvents, func(event1 models.VulnEvent, event2 models.VulnEvent) int {
		return event1.CreatedAt.Compare(event2.CreatedAt)
	})

	// now we can extract the first release and current release timestamp that being the first and last event

	tracking.InitialReleaseDate = asset.CreatedAt.Format(time.RFC3339)
	if len(allEvents) != 0 {
		tracking.CurrentReleaseDate = allEvents[len(allEvents)-1].CreatedAt.Format(time.RFC3339)
	} else {
		tracking.CurrentReleaseDate = tracking.InitialReleaseDate
	}

	// then we can construct the full revision history
	revisions, err := buildRevisionHistory(asset, allEvents, documentVersion)
	if err != nil {
		return tracking, err
	}
	tracking.RevisionHistory = revisions

	// fill in the last attributes
	version := fmt.Sprintf("%d", len(revisions))
	tracking.ID = fmt.Sprintf("csaf_report_%s_%s", strings.ToLower(asset.Slug), strings.ToLower(version))
	tracking.Version = version
	tracking.Status = "interim"
	return tracking, nil
}

// builds the full revision history for an object, that being a list of all changes to all vulnerabilities associated with this asset
func buildRevisionHistory(asset models.Asset, events []models.VulnEvent, documentVersion int) ([]revisionReplacement, error) {
	var revisions []revisionReplacement
	// we want to group all events based on their creation time to reduce entries and improve readability. accuracy = minutes
	timeBuckets := make(map[string][]models.VulnEvent, len(events))
	for _, event := range events {
		timeStamp := convertTimeToDateHourMinute(event.CreatedAt).Format(time.DateTime)
		timeBuckets[timeStamp] = append(timeBuckets[timeStamp], event)
	}

	// since maps are unordered data structures we need to convert it to a ordered one using slices
	eventGroups := make([][]models.VulnEvent, 0, len(events))
	for _, events := range timeBuckets {
		eventGroups = append(eventGroups, events)
	}

	// now we need to order the groups based on time
	// Disclaimer: technically this method is not 100% accurate since we make groups based on time.DateTime Format (only seconds) but then compare based on 5 digits precision seconds
	slices.SortFunc(eventGroups, func(events1 []models.VulnEvent, events2 []models.VulnEvent) int {
		return events1[0].CreatedAt.Compare(events2[0].CreatedAt)
	})

	// initial release entry with no vulnerabilities
	revisions = append(revisions, revisionReplacement{
		Date:    asset.CreatedAt.Format(time.RFC3339),
		Number:  "1",
		Summary: "Asset created, no vulnerabilities found",
	})

	// then just create a revision entry for every event group
	for i, eventGroup := range eventGroups {
		if i+1 >= documentVersion {
			break
		}
		revisionObject := revisionReplacement{
			Date: eventGroup[0].CreatedAt.Format(time.RFC3339),
		}
		revisionObject.Number = strconv.Itoa(i + 2)
		revisionObject.Summary = generateSummaryForEvents(eventGroup)
		revisions = append(revisions, revisionObject)
	}

	return revisions, nil
}

// generate a human readable summary to describe the changes of a revision entry
func generateSummaryForEvents(events []models.VulnEvent) string {
	slices.SortFunc(events, func(event1, event2 models.VulnEvent) int { return event1.CreatedAt.Compare(event2.CreatedAt) })
	acceptedVulns := []models.VulnEvent{}
	detectedVulns := []models.VulnEvent{}
	falsePositiveVulns := []models.VulnEvent{}
	fixedVulns := []models.VulnEvent{}
	reopenedVulns := []models.VulnEvent{}

	// put every event in their respective vuln type set
	for _, event := range events {
		switch event.Type {
		case models.EventTypeAccepted:
			acceptedVulns = append(acceptedVulns, event)
		case models.EventTypeDetected:
			detectedVulns = append(detectedVulns, event)
		case models.EventTypeFalsePositive:
			falsePositiveVulns = append(falsePositiveVulns, event)
		case models.EventTypeFixed:
			fixedVulns = append(fixedVulns, event)
		case models.EventTypeReopened:
			reopenedVulns = append(reopenedVulns, event)
		}
	}

	// then just write a textual description based on how many vulns are present from each vuln type
	summary := ""
	if len(detectedVulns) > 0 {
		if len(detectedVulns) == 1 {
			summary += fmt.Sprintf("Detected %d new vulnerability,", len(detectedVulns))
		} else {
			summary += fmt.Sprintf("Detected %d new vulnerabilities,", len(detectedVulns))
		}
	}
	if len(reopenedVulns) > 0 {
		if len(reopenedVulns) == 1 {
			summary += fmt.Sprintf(" Reopened %d old vulnerability,", len(reopenedVulns))
		} else {
			summary += fmt.Sprintf(" Reopened %d old vulnerabilities,", len(reopenedVulns))
		}
	}
	if len(fixedVulns) > 0 {
		if len(fixedVulns) == 1 {
			summary += fmt.Sprintf(" Fixed %d existing vulnerability,", len(fixedVulns))
		} else {
			summary += fmt.Sprintf(" Fixed %d existing vulnerabilities,", len(fixedVulns))
		}
	}
	if len(acceptedVulns) > 0 {
		if len(acceptedVulns) == 1 {
			summary += fmt.Sprintf(" Accepted %d existing vulnerability,", len(acceptedVulns))
		} else {
			summary += fmt.Sprintf(" Accepted %d existing vulnerabilities,", len(acceptedVulns))
		}
	}
	if len(falsePositiveVulns) > 0 {
		if len(falsePositiveVulns) == 1 {
			summary += fmt.Sprintf(" Marked %d existing vulnerability as false positive", len(falsePositiveVulns))
		} else {
			summary += fmt.Sprintf(" Marked %d existing vulnerabilities as false positives", len(falsePositiveVulns))
		}
	}
	summary = strings.TrimLeft(summary, " ")
	summary = strings.TrimRight(summary, ",")
	summary += "."
	return summary
}

// small helper function to extract the version from the file name of a csaf report
func extractVersionFromDocumentID(id string) (int, error) {
	fields := strings.Split(id, "_")
	if len(fields) <= 2 {
		return 0, fmt.Errorf("invalid csaf document ID")
	}
	version := fields[len(fields)-1]
	index := strings.Index(version, ".")
	if index == -1 {
		return 0, fmt.Errorf("invalid file name syntax")
	}
	version = version[:index]
	return strconv.Atoi(version)
}

// small helper function to eliminate seconds by rounding up to the next minute
func convertTimeToDateHourMinute(t time.Time) time.Time {
	return t.Add(time.Second * time.Duration(60-t.Second()))
}
