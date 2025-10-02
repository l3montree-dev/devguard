package csaf

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type csaf_controller struct {
	DB                       core.DB
	DependencyVulnRepository core.DependencyVulnRepository
	VulnEventRepository      core.VulnEventRepository
	AssetVersionRepository   core.AssetVersionRepository
}

// root struct of the document
type csaf struct {
	Document        documentObject  `json:"document,omitempty"`
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

func NewCSAFController(db core.DB, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository, assetVersionRepository core.AssetVersionRepository) *csaf_controller {
	return &csaf_controller{
		DB:                       db,
		DependencyVulnRepository: dependencyVulnRepository,
		VulnEventRepository:      vulnEventRepository,
		AssetVersionRepository:   assetVersionRepository,
	}
}

func (controller *csaf_controller) GetIndexHTML(ctx core.Context) error {
	html := `<html>
	<head><title>Index of /csaf/</title></head>
	<body cz-shortcut-listen="true">
	<h1>Index of /csaf/</h1><hr><pre>
	<a href="openpgp/">openpgp/</a>
	<a href="white/">white/</a>
	<a href="provider-metadata.json">provider-metadata.json</a>
	</pre><hr>
	</body>
	</html>`
	return ctx.HTML(200, html)
}

func (controller *csaf_controller) GetOpenPGP(ctx core.Context) error {
	html := `<html>
	<head><title>Index of /csaf/openpgp/</title></head>
	<body cz-shortcut-listen="true">
	<h1>Index of /csaf/openpgp</h1><hr><pre>
	<a href="public_key.asc">public_key.asc</a>
	<a href="public_key.sha512">public_key.asc.sha512</a>
	</pre><hr>
	</body>
	</html>`
	return ctx.HTML(200, html)
}

func (controller *csaf_controller) GetOpenPGPFile(ctx core.Context) error {
	file := ctx.Param("file")
	file = file[:len(file)-1]
	index := strings.LastIndex(file, ".")
	if index == -1 {
		return fmt.Errorf("invalid resource: %s", file)
	}
	extension := file[index:] //get the file extension
	if extension != ".asc" && extension != ".sha512" {
		return fmt.Errorf("invalid resource: %s", file)
	}
	publicKey := os.Getenv("CSAF_PUBLIC_KEY")
	if publicKey == "" {
		return fmt.Errorf("could read public key from env variables, make sure the variable <CSAF_PUBLIC_KEY> is set in the .env file of your project")
	}
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return err
	}
	pem := []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n")
	pem = append(pem, decodedPublicKey...)
	pem = append(pem, []byte("\n-----END PGP PUBLIC KEY BLOCK-----")...)
	if extension == ".asc" {
		return ctx.String(200, string(pem))
	} else if extension == ".sha512" {
		hash := sha512.Sum512(pem)
		hashString := hex.EncodeToString(hash[:])
		return ctx.String(200, hashString)
	}
	return fmt.Errorf("invalid resource: %s", file)
}

func (controller *csaf_controller) GenerateCSAFReport(ctx core.Context) error {
	slog.Info("start generating CSAF Document")

	csafDoc := csaf{}
	org := core.GetOrg(ctx)
	asset := core.GetAsset(ctx)
	csafDoc.Document = documentObject{
		Category:    "csaf_security_advisory",
		CSAFVersion: "2.0",
		Publisher: publisherReplacement{
			Category:  "vendor",
			Name:      org.Slug,
			Namespace: "https://devguard.org",
		},
		Title:    fmt.Sprintf("Vulnerability history of asset: %s", asset.Slug),
		Language: utils.Ptr("en-US"),
		Distribution: &distributionReplacement{
			TLP: struct {
				Label string "json:\"label,omitempty\""
				URL   string "json:\"url,omitempty\""
			}{
				Label: "WHITE",
				URL:   "https://first.org/tlp",
			},
		},
	}
	tracking, err := generateTrackingObject(asset, controller.DependencyVulnRepository, controller.VulnEventRepository)
	if err != nil {
		return err
	}
	csafDoc.Document.Tracking = tracking
	tree, err := generateProductTree(asset, controller.AssetVersionRepository)
	if err != nil {
		return err
	}
	csafDoc.ProductTree = &tree

	vulnerabilities, err := generateVulnerabilitiesObject(asset, controller.DependencyVulnRepository, controller.VulnEventRepository)
	if err != nil {
		return err
	}
	csafDoc.Vulnerabilities = vulnerabilities
	buf := bytes.Buffer{}

	encoder := json.NewEncoder(&buf)
	err = encoder.Encode(csafDoc)
	if err != nil {
		return err
	}
	hash := sha512.Sum512(buf.Bytes())

	fdCSAF, err := os.Create(csafDoc.Document.Tracking.ID + ".json")
	if err != nil {
		return err
	}
	defer fdCSAF.Close()
	_, err = io.Copy(fdCSAF, &buf)
	if err != nil {
		return err
	}

	hashString := hex.EncodeToString(hash[:])

	fdHash, err := os.Create(csafDoc.Document.Tracking.ID + ".json.sha512")
	if err != nil {
		return err
	}
	defer fdHash.Close()

	_, err = fdHash.WriteString(hashString)
	if err != nil {
		return err
	}

	err = generateProviderMetadataFile()

	slog.Info("successfully generated CSAF Document")
	return nil
}

func generateProviderMetadataFile() error {
	return nil
}

func generateProductTree(asset models.Asset, assetVersionRepository core.AssetVersionRepository) (productTree, error) {
	tree := productTree{}
	assetVersions, err := assetVersionRepository.GetAllTagsAndDefaultBranchForAsset(nil, asset.ID)
	if err != nil {
		return tree, err
	}

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

func generateVulnerabilitiesObject(asset models.Asset, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository) ([]vulnerability, error) {
	vulnerabilites := []vulnerability{}
	vulns, err := dependencyVulnRepository.GetAllVulnsForTagsAndDefaultBranchInAsset(nil, asset.ID, []models.VulnState{models.VulnStateFixed})
	if err != nil {
		return nil, err
	}
	// maps a cve ID to a set of asset versions where it is present
	cveGroups := make(map[string][]models.DependencyVuln)
	for _, vuln := range vulns {
		cveGroups[*vuln.CVEID] = append(cveGroups[*vuln.CVEID], vuln)
	}
	// then make a vulnerability object for every cve and list the asset version in the product status property
	for cve, vulns := range cveGroups {
		vulnObject := vulnerability{
			CVE:   cve,
			Title: cve,
		}
		uniqueVersionsAffected := make([]string, 0, len(vulns))
		for _, vuln := range vulns {
			if !slices.Contains(uniqueVersionsAffected, vuln.AssetVersionName) {
				uniqueVersionsAffected = append(uniqueVersionsAffected, vuln.AssetVersionName)
			}
		}
		vulnObject.ProductStatus = productStatusReplacement{
			KnownAffected: uniqueVersionsAffected,
		}

		vulnObject.Notes = generateNoteForVulnerabilityObject(vulns)
		vulnerabilites = append(vulnerabilites, vulnObject)
	}
	return vulnerabilites, nil
}

func generateNoteForVulnerabilityObject(vulns []models.DependencyVuln) []note {
	vulnDetails := note{
		Category: "details",
		Title:    "state of the vulnerability in the product",
	}
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
				summary += "Unhandled for purl " + *vuln.ComponentPurl + ", "
			case models.VulnStateAccepted:
				summary += "Accepted for purl " + *vuln.ComponentPurl + ", "
			case models.VulnStateFalsePositive:
				summary += "Marked as false positive for purl " + *vuln.ComponentPurl + ", "
			}
		}
		summary = strings.TrimRight(summary, ", ")
		summary += "| "
	}
	summary = strings.TrimRight(summary, "| ")
	vulnDetails.Text = summary
	return []note{vulnDetails}
}

func generateTrackingObject(asset models.Asset, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository) (trackingObject, error) {
	tracking := trackingObject{}
	// first get all dependency vulns for an asset
	vulns, err := dependencyVulnRepository.GetAllVulnsByAssetID(nil, asset.ID)
	if err != nil {
		return tracking, err
	}
	// then get all events for each of those vulns
	allEvents := make([]models.VulnEvent, 0, len(vulns))
	for _, vuln := range vulns {
		events, err := vulnEventRepository.GetSecurityRelevantEventsForVulnID(nil, vuln.ID)
		if err != nil {
			return tracking, err
		}
		allEvents = append(allEvents, events...)
	}
	// then we want to sort all events by their created_at timestamp
	slices.SortFunc(allEvents, func(event1 models.VulnEvent, event2 models.VulnEvent) int {
		return event1.CreatedAt.Compare(event2.CreatedAt)
	})

	// now we can extract the first release and current release timestamp that being the first and last event
	tracking.InitialReleaseDate = allEvents[0].CreatedAt.Format(time.RFC3339)
	tracking.CurrentReleaseDate = allEvents[len(allEvents)-1].CreatedAt.Format(time.RFC3339)
	// then we can construct the full revision history
	revisions, err := buildRevisionHistory(allEvents)
	if err != nil {
		return tracking, err
	}
	tracking.RevisionHistory = revisions
	version := fmt.Sprintf("%d", len(revisions))
	tracking.ID = fmt.Sprintf("csaf_report_%s_%s", strings.ToLower(asset.Slug), strings.ToLower(version))
	tracking.Version = version
	tracking.Status = "interim"
	return tracking, nil
}

func buildRevisionHistory(events []models.VulnEvent) ([]revisionReplacement, error) {
	var revisions []revisionReplacement
	// we want to group all events based on their creation time to reduce entries and improve readability
	timeBuckets := make(map[string][]models.VulnEvent, len(events))
	for _, event := range events {
		timeBuckets[event.CreatedAt.Format(time.DateTime)] = append(timeBuckets[event.CreatedAt.Format(time.DateTime)], event)
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

	// then just create a revision entry for every event group
	for i, eventGroup := range eventGroups {
		revisionObject := revisionReplacement{
			Date: eventGroup[0].CreatedAt.Format(time.RFC3339),
		}
		revisionObject.Number = strconv.Itoa(i + 1)
		revisionObject.Summary = generateSummaryForEvents(eventGroup)
		revisions = append(revisions, revisionObject)
	}

	return revisions, nil
}

func generateSummaryForEvents(events []models.VulnEvent) string {
	acceptedVulns := []models.VulnEvent{}
	detectedVulns := []models.VulnEvent{}
	falsePositiveVulns := []models.VulnEvent{}
	fixedVulns := []models.VulnEvent{}
	reopenedVulns := []models.VulnEvent{}
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
	summary := ""
	if len(detectedVulns) > 0 {
		summary += fmt.Sprintf("Detected %d new vulnerabilities,", len(detectedVulns))
	}
	if len(reopenedVulns) > 0 {
		summary += fmt.Sprintf(" Reopened %d old vulnerabilities,", len(reopenedVulns))
	}
	if len(fixedVulns) > 0 {
		summary += fmt.Sprintf(" Fixed %d existing vulnerabilities,", len(fixedVulns))
	}
	if len(acceptedVulns) > 0 {
		summary += fmt.Sprintf(" Accepted %d existing vulnerabilities,", len(acceptedVulns))
	}
	if len(falsePositiveVulns) > 0 {
		summary += fmt.Sprintf(" Marked %d existing vulnerabilities as false positives", len(falsePositiveVulns))
	}
	summary = strings.TrimLeft(summary, " ")
	summary = strings.TrimRight(summary, ",")
	summary += "."
	return summary
}
