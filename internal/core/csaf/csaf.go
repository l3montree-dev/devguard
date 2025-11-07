package csaf

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"maps"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	pgpCrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

const PRETTY_JSON_INDENT = "    "

type csafController struct {
	dependencyVulnRepository core.DependencyVulnRepository
	vulnEventRepository      core.VulnEventRepository
	assetVersionRepository   core.AssetVersionRepository
	assetRepository          core.AssetRepository
	projectRepository        core.ProjectRepository
	organizationRepository   core.OrganizationRepository
	cveRepository            core.CveRepository
	artifactRepository       core.ArtifactRepository
}

func NewCSAFController(dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository, assetVersionRepository core.AssetVersionRepository, assetRepository core.AssetRepository, projectRepository core.ProjectRepository, organizationRepository core.OrganizationRepository, cveRepository core.CveRepository, artifactRepository core.ArtifactRepository) *csafController {
	return &csafController{
		dependencyVulnRepository: dependencyVulnRepository,
		vulnEventRepository:      vulnEventRepository,
		assetVersionRepository:   assetVersionRepository,
		assetRepository:          assetRepository,
		projectRepository:        projectRepository,
		organizationRepository:   organizationRepository,
		cveRepository:            cveRepository,
		artifactRepository:       artifactRepository,
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
	tracking, _, err := generateTrackingObject(asset, controller.dependencyVulnRepository, controller.vulnEventRepository, math.MaxInt)
	if err != nil {
		return err
	}

	// then write each revision entry version to the index string
	index := ""
	for _, entry := range tracking.RevisionHistory {
		year := (*entry.Date)[:4]
		fileName := fmt.Sprintf("csaf_report_%s_%s.json", strings.ToLower(asset.Slug), strings.ToLower(string(*entry.Number)))
		index += fmt.Sprintf("%s/%s\n", year, fileName)
	}
	return ctx.String(200, index)
}

// builds and returns the changes.csv file, containing all reports ordered by release dates
func (controller *csafController) GetChangesCSVFile(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	// build revision history first
	tracking, _, err := generateTrackingObject(asset, controller.dependencyVulnRepository, controller.vulnEventRepository, math.MaxInt)
	if err != nil {
		return err
	}

	// sort resulting revision history by date in descending order
	slices.SortFunc(tracking.RevisionHistory, func(revision1, revision2 *gocsaf.Revision) int {
		time1, _ := time.Parse(time.RFC3339, *revision1.Date) //nolint:all
		time2, _ := time.Parse(time.RFC3339, *revision2.Date) //nolint:all
		return time1.Compare(time2) * -1
	})

	// then write each entry to the csv string and return the result
	csvContents := ""
	for _, entry := range tracking.RevisionHistory {
		year := (*entry.Date)[:4]
		fileName := fmt.Sprintf("csaf_report_%s_%s.json", strings.ToLower(asset.Slug), strings.ToLower(string(*entry.Number)))
		csvContents += fmt.Sprintf("\"%s/%s\",\"%s\"\n", year, fileName, *entry.Date)
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
	fingerprint := getPublicKeyFingerprint()

	type pageData struct {
		Fingerprint string
	}
	data := pageData{Fingerprint: fingerprint}

	htmlTemplate := `<html>
	<head><title>Index of /csaf/openpgp/</title></head>
	<body cz-shortcut-listen="true">
	<h1>Index of /csaf/openpgp</h1><hr><pre>
	<a href="../">../</a>
	<a href="{{ .Fingerprint }}.asc" download="{{ .Fingerprint }}.asc">{{ .Fingerprint }}.asc</a>
	<a href="{{ .Fingerprint }}.asc.sha512" download="{{ .Fingerprint }}.asc.sha512">{{ .Fingerprint }}.asc.sha512</a>
	</pre><hr>
	</body>
	</html>`

	tmpl := template.Must(template.New("fingerprint").Parse(htmlTemplate))
	buf := bytes.Buffer{}

	err := tmpl.Execute(&buf, data)
	if err != nil {
		return err
	}

	return ctx.HTML(200, buf.String())
}

// returns the set of all years where new csaf versions where published
func getAllYears(asset models.Asset, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository) ([]int, error) {
	vulns, err := dependencyVulnRepository.GetAllVulnsByAssetID(nil, asset.ID)
	if err != nil {
		return nil, err
	}
	// iterate over every event = version, check the release year and append if not already present
	allYears := make([]int, 0)
	if err != nil {
		return nil, err
	}
	// build a map
	allYearsMap := map[int]struct{}{
		asset.CreatedAt.Year(): {},
	}

	events := utils.Flat(utils.Map(vulns, func(el models.DependencyVuln) []models.VulnEvent {
		return el.Events
	}))

	for _, event := range events {
		year := event.CreatedAt.Year()
		allYearsMap[year] = struct{}{}
	}

	for year := range allYearsMap {
		allYears = append(allYears, year)
	}

	slices.Sort(allYears)
	return allYears, nil
}

// builds and returns the html used to display every directory in the tlp white folder
func (controller *csafController) GetTLPWhiteEntriesHTML(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	// get all years where csaf version were published and make a directory for each of these
	allYears, err := getAllYears(asset, controller.dependencyVulnRepository, controller.vulnEventRepository)
	if err != nil {
		return err
	}

	type pageData struct {
		Years []int
	}
	data := pageData{Years: allYears}
	htmlTemplate := `
<html>
<head><title>Index of /csaf/white/</title></head>
<body cz-shortcut-listen="true">
<h1>Index of /csaf/white/</h1>
<hr>
<pre>
<a href="../">../</a>

{{ range .Years }}
<a href="{{ . }}/">{{ . }}/</a>
{{ end }}

<a href="index.txt/" download="index.txt">index.txt</a>
<a href="changes.csv/" download="changes.csv">changes.csv</a>
</pre>
<hr>
</body>
</html>`

	tmpl := template.Must(template.New("years").Parse(htmlTemplate))

	buf := bytes.Buffer{}
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return err
	}

	return ctx.HTML(200, buf.String())
}

// builds and returns the html to display every csaf version of a given year as well as the signature and hash
func (controller *csafController) GetReportsByYearHTML(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	// extract the requested year and build the revision history first
	year := strings.TrimRight(ctx.Param("year"), "/")
	tracking, _, err := generateTrackingObject(asset, controller.dependencyVulnRepository, controller.vulnEventRepository, math.MaxInt)
	if err != nil {
		return err
	}

	// then filter each csaf version if they are released in the given year
	entriesForYear := make([]*gocsaf.Revision, 0)
	yearNumber, err := strconv.Atoi(year)
	if err != nil {
		return err
	}

	for _, entry := range tracking.RevisionHistory {
		date, err := time.Parse(time.RFC3339, *entry.Date)
		if err != nil {
			return err
		}
		if date.Year() == yearNumber {
			entriesForYear = append(entriesForYear, entry)
		}
	}

	type pageData struct {
		Year      int
		Filenames []string
	}
	data := pageData{Year: yearNumber, Filenames: make([]string, 0, len(entriesForYear))}
	for _, entry := range entriesForYear {
		data.Filenames = append(data.Filenames, fmt.Sprintf("csaf_report_%s_%s.json", strings.ToLower(asset.Slug), strings.ToLower(string(*entry.Number))))
	}

	// generate the htmlTemplate for each version as well as the signature and hash
	htmlTemplate := `
<html>
<head><title>Index of /csaf/white/{{ .Year }}/</title></head>
<body cz-shortcut-listen="true">
<h1>Index of /csaf/white/{{ .Year }}/</h1>
<hr>
<pre>
<a href="../">../</a>
{{ range .Filenames }}
<a href="{{ . }}" download="{{ . }}">{{ . }}</a>
<a href="{{ . }}.asc" download="{{ . }}.asc">{{ . }}.asc</a>
<a href="{{ . }}.sha256" download="{{ . }}.sha256">{{ . }}.sha256</a>
<a href="{{ . }}.sha512" download="{{ . }}.sha512">{{ . }}.sha512</a>
{{ end }}
</pre>
<hr>
</body>
</html>
`

	tmpl := template.Must(template.New("entries").Parse(htmlTemplate))

	buf := bytes.Buffer{}
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return err
	}

	return ctx.HTML(200, buf.String())
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

// returns the aggregator file which points to all public organizations provider-metadata files
func (controller *csafController) GetAggregatorJSON(ctx core.Context) error {
	aggregatorObject := gocsaf.AggregatorInfo{
		Category:       utils.Ptr(gocsaf.AggregatorLister),
		ContactDetails: "info@l3montree.com",
		Name:           "L3montree GmbH",
		Namespace:      "L3montree.com",
	}

	hostURL := os.Getenv("API_URL")
	if hostURL == "" {
		return fmt.Errorf("could not get api url from environment variables, check the API_URL variable in the .env file")
	}
	csafAggregatorURL := fmt.Sprintf("%s/api/v1/.well-known/csaf-aggregator/", hostURL)
	aggregator := gocsaf.Aggregator{
		Aggregator:   &aggregatorObject,
		Version:      utils.Ptr(gocsaf.AggregatorVersion20),
		CanonicalURL: utils.Ptr(gocsaf.AggregatorURL(csafAggregatorURL + "aggregator.json")),
		LastUpdated:  utils.Ptr(gocsaf.TimeStamp(time.Now())),
	}

	orgs, err := controller.organizationRepository.GetOrgsWithVulnSharingAssets()
	if err != nil {
		return err
	}

	// for every org build an entry if they have the csaf report publicly available
	providers := make([]gocsaf.AggregatorCSAFProviderMetadata, 0)
	for _, org := range orgs {
		// if org.PublishCSAF == true {}...
		orgCSAFURL := fmt.Sprintf("%s/api/v1/organizations/%s/csaf/provider-metadata.json/", hostURL, org.Slug)
		metadata := gocsaf.AggregatorCSAFProviderMetadata{
			Publisher: &gocsaf.Publisher{
				Category:  utils.Ptr(gocsaf.CSAFCategoryVendor),
				Name:      &org.Slug,
				Namespace: utils.Ptr(os.Getenv("API_URL")),
			},
			Role:        utils.Ptr(gocsaf.MetadataRoleTrustedProvider),
			URL:         utils.Ptr(gocsaf.ProviderURL(orgCSAFURL)),
			LastUpdated: utils.Ptr(gocsaf.TimeStamp(time.Now())),
		}
		providers = append(providers, metadata)
	}

	// then append each metadata as provider object to the aggregator provider list
	for _, entry := range providers {
		aggregator.CSAFProviders = append(aggregator.CSAFProviders, &gocsaf.AggregatorCSAFProvider{
			Metadata: &entry,
		})
	}

	return ctx.JSONPretty(200, aggregator, PRETTY_JSON_INDENT)
}

// returns the provider-metadata file for an organization which points to each assets provider-metadata
func (controller *csafController) GetProviderMetadataForOrganization(ctx core.Context) error {
	org := core.GetOrg(ctx)
	hostURL := os.Getenv("API_URL")
	csafURL := fmt.Sprintf("%s/api/v1/organizations/%s/csaf/", hostURL, org.Slug)

	fingerprint := getPublicKeyFingerprint()

	metadata := gocsaf.ProviderMetadata{
		CanonicalURL: utils.Ptr(gocsaf.ProviderURL(csafURL + "provider-metadata.json")),
		LastUpdated:  utils.Ptr(gocsaf.TimeStamp(time.Now())),

		ListOnCSAFAggregators:   utils.Ptr(true), // TODO check if reports are published
		MirrorOnCSAFAggregators: utils.Ptr(true), // TODO check if reports are published
		MetadataVersion:         utils.Ptr(gocsaf.MetadataVersion20),
		PGPKeys:                 []gocsaf.PGPKey{{Fingerprint: gocsaf.Fingerprint(fingerprint), URL: utils.Ptr(csafURL + "openpgp/" + fingerprint + ".asc")}},
		Role:                    utils.Ptr(gocsaf.MetadataRoleTrustedProvider),
		Publisher: &gocsaf.Publisher{
			Category:       utils.Ptr(gocsaf.CSAFCategoryVendor),
			ContactDetails: utils.SafeDereference(org.ContactPhoneNumber),
			Name:           &org.Name,
			Namespace:      utils.Ptr(os.Getenv("API_URL")), // TODO add option to add namespace to an org
		},
	}
	assets, err := controller.assetRepository.GetAssetsWithVulnSharingEnabled(org.ID)
	if err != nil {
		return echo.NewHTTPError(404, "organization not found")
	}
	if len(assets) == 0 {
		return echo.NewHTTPError(404, "organization not found")
	}

	distributions := make([]gocsaf.Distribution, 0)
	for _, asset := range assets {
		distribution := gocsaf.Distribution{
			// Summary:  "location of provider-metadata.json for asset: " + asset.Name,
			// TLPLabel: "WHITE",
			DirectoryURL: fmt.Sprintf("%s/api/v1/organizations/%s/projects/%s/assets/%s/csaf/provider-metadata.json", hostURL, org.Slug, asset.Project.Slug, asset.Slug),
		}
		distributions = append(distributions, distribution)
	}
	metadata.Distributions = distributions

	return ctx.JSONPretty(200, metadata, PRETTY_JSON_INDENT)
}

// returns the provider metadata file for a given asset which points to the location of the tlp white csaf reports
func (controller *csafController) GetProviderMetadataForAsset(ctx core.Context) error {
	organization := core.GetOrg(ctx)
	project := core.GetProject(ctx)
	asset := core.GetAsset(ctx)
	hostURL := os.Getenv("API_URL")
	if hostURL == "" {
		return fmt.Errorf("could not get api url from environment variables, check the API_URL variable in the .env file")
	}
	csafURL := fmt.Sprintf("%s/api/v1/organizations/%s/projects/%s/assets/%s/csaf/", hostURL, organization.Slug, project.Slug, asset.Slug)

	fingerprint := getPublicKeyFingerprint()

	metadata := gocsaf.ProviderMetadata{
		CanonicalURL:            utils.Ptr(gocsaf.ProviderURL(csafURL + "provider-metadata.json")),
		LastUpdated:             utils.Ptr(gocsaf.TimeStamp(time.Now())),
		ListOnCSAFAggregators:   utils.Ptr(true),
		MirrorOnCSAFAggregators: utils.Ptr(true),
		Role:                    utils.Ptr(gocsaf.MetadataRoleTrustedProvider),
		MetadataVersion:         utils.Ptr(gocsaf.MetadataVersion20),
		Publisher: &gocsaf.Publisher{
			Category:       utils.Ptr(gocsaf.CSAFCategoryVendor),
			ContactDetails: "info@l3montree.com",
			Name:           utils.Ptr("L3montree GmbH"),
			Namespace:      utils.Ptr("https://l3montree.com/"),
		},
		PGPKeys: []gocsaf.PGPKey{{Fingerprint: gocsaf.Fingerprint(fingerprint), URL: utils.Ptr(csafURL + "openpgp/" + fingerprint + ".asc")}},
		Distributions: []gocsaf.Distribution{
			{
				// TLPLabel: "WHITE",
				DirectoryURL: csafURL + "white/",
			},
		},
	}

	return ctx.JSONPretty(200, metadata, PRETTY_JSON_INDENT)
}

func getPublicKeyFingerprint() string {
	return os.Getenv("CSAF_OPENPGP_FINGERPRINT")
}

// from here on: code that handles the creation of csaf reports them self

// handles all requests directed at a specific csaf report version, including the csaf report itself as well as the respective hash and signature
func (controller *csafController) ServeCSAFReportRequest(ctx core.Context) error {
	// generate the report first
	csafReport, err := generateCSAFReport(ctx, controller.dependencyVulnRepository, controller.vulnEventRepository, controller.assetVersionRepository, controller.cveRepository, controller.artifactRepository)
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
		return ctx.JSONPretty(200, csafReport, PRETTY_JSON_INDENT)
	case "asc":
		// return the signature of the json encoding of the report
		buf := bytes.Buffer{}
		encoder := json.NewEncoder(&buf)
		encoder.SetIndent("", PRETTY_JSON_INDENT)
		err = encoder.Encode(csafReport)
		if err != nil {
			return err
		}
		signature, err := signCSAFReport(buf.Bytes())
		if err != nil {
			return err
		}
		return ctx.String(200, string(signature))
	case "sha256":
		// return the hash of the report
		buf := bytes.Buffer{}
		encoder := json.NewEncoder(&buf)
		encoder.SetIndent("", PRETTY_JSON_INDENT)
		err = encoder.Encode(csafReport)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(buf.Bytes())
		hashString := hex.EncodeToString(hash[:])
		return ctx.String(200, hashString)
	case "sha512":
		// return the hash of the report
		buf := bytes.Buffer{}
		encoder := json.NewEncoder(&buf)
		encoder.SetIndent("", PRETTY_JSON_INDENT)
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
func generateCSAFReport(ctx core.Context, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository, assetVersionRepository core.AssetVersionRepository, cveRepository core.CveRepository, artifactRepository core.ArtifactRepository) (gocsaf.Advisory, error) {
	csafDoc := gocsaf.Advisory{}
	// extract context information
	version, err := extractVersionFromDocumentID(ctx.Param("version"))
	if err != nil {
		return csafDoc, err
	}
	org := core.GetOrg(ctx)
	asset := core.GetAsset(ctx)

	// build trivial parts of the document field
	csafDoc.Document = &gocsaf.Document{
		CSAFVersion: utils.Ptr(gocsaf.CSAFVersion20),
		Publisher: &gocsaf.DocumentPublisher{
			Category:  utils.Ptr(gocsaf.CSAFCategoryVendor),
			Name:      &org.Name,
			Namespace: utils.Ptr("https://devguard.org"),
		},
		Title:      utils.Ptr(fmt.Sprintf("Vulnerability history of asset: %s", asset.Slug)),
		SourceLang: utils.Ptr(gocsaf.Lang("en-US")),
	}

	// TODO change tlp based off of visibility of csaf report, white for public and TLP:AMBER or TLP:RED for access protected reports
	csafDoc.Document.Distribution = &gocsaf.DocumentDistribution{
		TLP: &gocsaf.TLP{
			DocumentTLPLabel: utils.Ptr(gocsaf.TLPLabel(gocsaf.TLPLabelWhite)),
			URL:              utils.Ptr("https://first.org/tlp"),
		},
	}

	tracking, vulns, err := generateTrackingObject(asset, dependencyVulnRepository, vulnEventRepository, version)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.Document.Tracking = &tracking

	tree, err := generateProductTree(asset, assetVersionRepository, artifactRepository)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.ProductTree = &tree

	// get the timestamp of the last revision which we need to time travel to
	lastRevisionTimestamp, err := time.Parse(time.RFC3339, *tracking.RevisionHistory[len(tracking.RevisionHistory)-1].Date)
	if err != nil {
		return csafDoc, err
	}
	vulnerabilities, err := generateVulnerabilityObjects(lastRevisionTimestamp, vulns)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.Vulnerabilities = vulnerabilities

	// if we do not have any vulnerabilities we do not comply with the security framework anymore so we need to switch the category to the base profile
	if len(vulnerabilities) == 0 {
		csafDoc.Document.Category = utils.Ptr(gocsaf.DocumentCategory("csaf_base"))
	} else {
		csafDoc.Document.Category = utils.Ptr(gocsaf.DocumentCategory("csaf_vex"))
	}

	csafDoc.Document.Tracking.CurrentReleaseDate = csafDoc.Document.Tracking.RevisionHistory[len(csafDoc.Document.Tracking.RevisionHistory)-1].Date

	return csafDoc, nil
}

// generates the product tree object for a specific asset, which includes the default branch as well as all tags
func generateProductTree(asset models.Asset, assetVersionRepository core.AssetVersionRepository, artifactRepository core.ArtifactRepository) (gocsaf.ProductTree, error) {
	tree := gocsaf.ProductTree{}
	assetVersions, err := assetVersionRepository.GetAllTagsAndDefaultBranchForAsset(nil, asset.ID)
	if err != nil {
		return tree, err
	}

	assetVersionNames := utils.Map(assetVersions, func(el models.AssetVersion) string {
		return el.Name
	})

	artifacts, err := artifactRepository.GetByAssetVersions(asset.ID, assetVersionNames)
	if err != nil {
		return tree, err
	}

	// append each relevant asset version
	for _, artifact := range artifacts {
		branch := gocsaf.Branch{
			Category: utils.Ptr(gocsaf.CSAFBranchCategoryProductVersion),
			Name:     utils.Ptr(artifact.ArtifactName + "@" + artifact.AssetVersionName),
			Product: &gocsaf.FullProductName{
				Name:      utils.Ptr(artifact.ArtifactName + "@" + artifact.AssetVersionName),
				ProductID: utils.Ptr(gocsaf.ProductID(artifact.ArtifactName + "@" + artifact.AssetVersionName)),
			},
		}
		tree.Branches = append(tree.Branches, &branch)
	}

	return tree, nil
}

// generates the vulnerability object for a specific asset at a certain timeStamp in time
func generateVulnerabilityObjects(timeStamp time.Time, allVulnsOfAsset []models.DependencyVuln) ([]*gocsaf.Vulnerability, error) {
	vulnerabilities := []*gocsaf.Vulnerability{}
	timeStamp = convertTimeToDateHourMinute(timeStamp)
	// first get all vulns
	filteredVulns := make([]models.DependencyVuln, 0, len(allVulnsOfAsset))
	for _, vuln := range allVulnsOfAsset {
		if vuln.CreatedAt.Before(timeStamp) {
			filteredVulns = append(filteredVulns, vuln)
		}
	}
	if len(filteredVulns) == 0 {
		return vulnerabilities, nil
	}

	lastEvents := map[string]models.VulnEvent{}
	// then time travel each vuln to the state at timeStamp using the latest events
	for i, vuln := range filteredVulns {
		var lastEvent models.VulnEvent
		for i := len(vuln.Events) - 1; i >= 0; i-- {
			event := vuln.Events[i]
			if event.CreatedAt.Before(timeStamp) || event.CreatedAt.Equal(timeStamp) {
				lastEvent = event
				break
			}
		}
		lastEvent.Apply(&filteredVulns[i])
		lastEvents[vuln.ID] = lastEvent
	}

	// maps a cve ID to a set of asset versions where it is present to reduce clutter
	cveGroups := make(map[string][]models.DependencyVuln)
	for _, vuln := range filteredVulns {
		cveGroups[utils.SafeDereference(vuln.CVEID)] = append(cveGroups[utils.SafeDereference(vuln.CVEID)], vuln)
	}

	// then make a vulnerability object for every cve and list the asset version in the product status property
	for cve, vulnsInGroup := range cveGroups {
		vulnObject := gocsaf.Vulnerability{
			CVE:   utils.Ptr(gocsaf.CVE(cve)),
			Title: &cve,
		}
		affected := map[string]struct{}{}
		notAffected := map[string]struct{}{}
		fixed := map[string]struct{}{}
		underInvestigation := map[string]struct{}{}
		flags := []*gocsaf.Flag{}
		threats := []*gocsaf.Threat{}
		for _, vuln := range vulnsInGroup {
			// determine the discovery date
			if vulnObject.DiscoveryDate == nil {
				vulnObject.DiscoveryDate = utils.Ptr(vulnsInGroup[0].CreatedAt.Format(time.RFC3339))
			} else {
				currentDiscoveryDate, err := time.Parse(time.RFC3339, *vulnObject.DiscoveryDate)
				if err == nil {
					if currentDiscoveryDate.After(vuln.CreatedAt) {
						vulnObject.DiscoveryDate = utils.Ptr(vuln.CreatedAt.Format(time.RFC3339))
					}
				}
			}

			productIDs := utils.Map(vuln.Artifacts, func(v models.Artifact) *gocsaf.ProductID {
				return utils.Ptr(gocsaf.ProductID(fmt.Sprintf("%s@%s", v.ArtifactName, v.AssetVersionName)))
			})

			switch vuln.State {
			case models.VulnStateOpen:
				for _, pid := range productIDs {
					underInvestigation[string(*pid)] = struct{}{}
				}
			case models.VulnStateAccepted:
				threats = append(threats, &gocsaf.Threat{
					Category: utils.Ptr(gocsaf.CSAFThreatCategoryImpact),
					Details:  lastEvents[vuln.ID].Justification,
				})
				for _, pid := range productIDs {
					affected[string(*pid)] = struct{}{}
				}
			case models.VulnStateFixed:
				for _, pid := range productIDs {
					fixed[string(*pid)] = struct{}{}
				}
			case models.VulnStateFalsePositive:
				justification := string(lastEvents[vuln.ID].MechanicalJustification)
				if lastEvents[vuln.ID].MechanicalJustification == "" {
					justification = string(gocsaf.CSAFFlagLabelVulnerableCodeNotInExecutePath)
				}

				flags = append(flags, &gocsaf.Flag{
					Label:      utils.Ptr(gocsaf.FlagLabel(justification)),
					ProductIds: utils.Ptr(gocsaf.Products(productIDs)),
				})
				for _, pid := range productIDs {
					notAffected[string(*pid)] = struct{}{}
				}
			}
		}

		vulnObject.ProductStatus = &gocsaf.ProductStatus{
			Fixed: utils.Ptr(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(fixed)), func(el string) *gocsaf.ProductID {
				return utils.Ptr(gocsaf.ProductID(el))
			}))),
			KnownAffected: utils.Ptr(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(affected)), func(el string) *gocsaf.ProductID {
				return utils.Ptr(gocsaf.ProductID(el))
			}))),
			KnownNotAffected: utils.Ptr(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(notAffected)), func(el string) *gocsaf.ProductID {
				return utils.Ptr(gocsaf.ProductID(el))
			}))),
			UnderInvestigation: utils.Ptr(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(underInvestigation)), func(el string) *gocsaf.ProductID {
				return utils.Ptr(gocsaf.ProductID(el))
			}))),
		}
		vulnObject.Flags = flags
		vulnObject.Threats = threats

		notes, err := generateNotesForVulnerabilityObject(vulnsInGroup)
		if err != nil {
			return nil, err
		}
		vulnObject.Notes = notes
		vulnerabilities = append(vulnerabilities, &vulnObject)
	}

	slices.SortFunc(vulnerabilities, func(vuln1, vuln2 *gocsaf.Vulnerability) int {
		if vuln1.CVE == nil && vuln2.CVE == nil {
			return 0
		}
		if vuln1.CVE == nil {
			return 1
		}
		if vuln2.CVE == nil {
			return -1

		}
		return -strings.Compare(string(*vuln1.CVE), string(*vuln2.CVE))
	})
	return vulnerabilities, nil
}

// generate the textual summary for a vulnerability object
func generateNotesForVulnerabilityObject(vulns []models.DependencyVuln) ([]*gocsaf.Note, error) {
	if len(vulns) == 0 {
		return nil, nil
	}
	vulnDetails := gocsaf.Note{
		NoteCategory: utils.Ptr(gocsaf.CSAFNoteCategoryDetails),
		Title:        utils.Ptr("state of the vulnerability in the product"),
	}

	cve := vulns[0].CVE
	cveDescription := gocsaf.Note{
		NoteCategory: utils.Ptr(gocsaf.CSAFNoteCategoryDescription),
		Title:        utils.Ptr("textual description of CVE"),
		Text:         &cve.Description,
	}

	// group vulnerabilities by artifact
	artifactToVulns := map[string][]models.DependencyVuln{}
	for _, vuln := range vulns {
		for _, artifact := range vuln.Artifacts {
			key := fmt.Sprintf("%s@%s", artifact.ArtifactName, artifact.AssetVersionName)
			artifactToVulns[key] = append(artifactToVulns[key], vuln)
		}
	}

	// Generate summary for each artifact
	var summaryParts []string
	for artifact, vulns := range artifactToVulns {
		var vulnStates []string
		for _, vuln := range vulns {
			vulnStates = append(vulnStates, fmt.Sprintf("%s for package %s", stateToString(vuln.State), *vuln.ComponentPurl))
		}
		summaryParts = append(summaryParts, fmt.Sprintf("ProductID %s: %s", artifact, strings.Join(vulnStates, ", ")))
	}

	vulnDetails.Text = utils.Ptr(strings.Join(summaryParts, " | "))
	return gocsaf.Notes{&vulnDetails, &cveDescription}, nil
}

// Helper function to map state to human-readable string
func stateToString(state models.VulnState) string {
	switch state {
	case models.VulnStateOpen:
		return "unhandled"
	case models.VulnStateAccepted:
		return "accepted"
	case models.VulnStateFalsePositive:
		return "marked as false positive"
	case models.VulnStateFixed:
		return "fixed"
	default:
		return "unknown state"
	}
}

// generate the tracking object used by the document object
func generateTrackingObject(asset models.Asset, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository, documentVersion int) (gocsaf.Tracking, []models.DependencyVuln, error) {
	tracking := gocsaf.Tracking{}
	// first get all dependency vulns for an asset
	vulns, err := dependencyVulnRepository.GetAllVulnsByAssetID(nil, asset.ID)
	if err != nil {
		return tracking, vulns, err
	}

	// gather all events - and filter them to security relevant ones
	allEvents := utils.Flat(utils.Map(vulns, func(v models.DependencyVuln) []models.VulnEvent {
		return utils.Filter(v.Events, func(e models.VulnEvent) bool {
			return models.EventTypeAccepted == e.Type ||
				models.EventTypeDetected == e.Type ||
				models.EventTypeFixed == e.Type ||
				models.EventTypeReopened == e.Type ||
				models.EventTypeFalsePositive == e.Type
		})
	}))

	// sort them by their creation timestamp
	slices.SortFunc(allEvents, func(event1 models.VulnEvent, event2 models.VulnEvent) int {
		return event1.CreatedAt.Compare(event2.CreatedAt)
	})

	// now we can extract the first release and current release timestamp that being the first and last event
	tracking.InitialReleaseDate = utils.Ptr(asset.CreatedAt.Format(time.RFC3339))
	if len(allEvents) != 0 {
		tracking.CurrentReleaseDate = utils.Ptr(allEvents[len(allEvents)-1].CreatedAt.Format(time.RFC3339))
	} else {
		tracking.CurrentReleaseDate = tracking.InitialReleaseDate
	}

	// then we can construct the full revision history
	revisions, err := buildRevisionHistory(asset, allEvents, vulns, documentVersion, dependencyVulnRepository)
	if err != nil {
		return tracking, vulns, err
	}
	tracking.RevisionHistory = revisions

	// fill in the last attributes
	version := fmt.Sprintf("%d", len(revisions))
	tracking.ID = utils.Ptr(gocsaf.TrackingID(fmt.Sprintf("csaf_report_%s_%s", strings.ToLower(asset.Slug), strings.ToLower(version))))
	tracking.Version = utils.Ptr(gocsaf.RevisionNumber(version))
	tracking.Status = utils.Ptr(gocsaf.CSAFTrackingStatusInterim)
	return tracking, vulns, nil
}

// builds the full revision history for an object, that being a list of all changes to all vulnerabilities associated with this asset
func buildRevisionHistory(asset models.Asset, events []models.VulnEvent, vulns []models.DependencyVuln, documentVersion int, dependencyVulnRepository core.DependencyVulnRepository) ([]*gocsaf.Revision, error) {
	var revisions []*gocsaf.Revision
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
	revisions = append(revisions, &gocsaf.Revision{
		Date:    utils.Ptr(asset.CreatedAt.Format(time.RFC3339)),
		Number:  utils.Ptr(gocsaf.RevisionNumber("1")),
		Summary: utils.Ptr("Asset created, no vulnerabilities found"),
	})

	// then just create a revision entry for every event group
	for i, eventGroup := range eventGroups {
		if i+1 >= documentVersion {
			break
		}
		revisionObject := gocsaf.Revision{
			Date: utils.Ptr(eventGroup[0].CreatedAt.Format(time.RFC3339)),
		}
		revisionObject.Number = utils.Ptr(gocsaf.RevisionNumber(strconv.Itoa(i + 2)))
		summary, err := generateSummaryForEvents(eventGroup, vulns)
		if err != nil {
			return nil, err
		}
		revisionObject.Summary = &summary
		revisions = append(revisions, &revisionObject)
	}

	return revisions, nil
}

type vulnEventWithCVEID struct {
	Event models.VulnEvent
	CVEID string
}

func generateSummaryForEvents(events []models.VulnEvent, vulns []models.DependencyVuln) (string, error) {
	slices.SortFunc(events, func(event1, event2 models.VulnEvent) int {
		return event1.CreatedAt.Compare(event2.CreatedAt)
	})

	vulnMap := make(map[string]models.DependencyVuln)
	for _, vuln := range vulns {
		vulnMap[vuln.ID] = vuln
	}

	// Group events by type
	type vulnGroup struct {
		events []vulnEventWithCVEID
		desc   string
	}
	groups := map[models.VulnEventType]vulnGroup{
		models.EventTypeDetected:      {desc: "Detected %d new vulnerabilit%s (%s)"},
		models.EventTypeReopened:      {desc: "Reopened %d old vulnerabilit%s (%s)"},
		models.EventTypeFixed:         {desc: "Fixed %d existing vulnerabilit%s (%s)"},
		models.EventTypeAccepted:      {desc: "Accepted %d existing vulnerabilit%s (%s)"},
		models.EventTypeFalsePositive: {desc: "Marked %d existing vulnerabilit%s as false positive (%s)"},
	}

	for _, event := range events {
		vuln := vulnMap[event.VulnID]
		t := groups[event.Type]
		t.events = append(t.events, vulnEventWithCVEID{Event: event, CVEID: *vuln.CVEID})
		groups[event.Type] = t
	}

	// Helper to format a group's summary
	formatGroup := func(g vulnGroup) string {
		if len(g.events) == 0 {
			return ""
		}
		cveIDs := make([]string, len(g.events))
		for i, e := range g.events {
			cveIDs[i] = e.CVEID
		}
		plural := "ies"
		if len(g.events) == 1 {
			plural = "y"
		}
		slices.Sort(cveIDs)
		return fmt.Sprintf(g.desc, len(g.events), plural, strings.Join(cveIDs, ", "))
	}

	// sort the groups by event type for consistent output

	// Build summary
	summaryParts := []string{}
	for _, group := range groups {
		if part := formatGroup(group); part != "" {
			summaryParts = append(summaryParts, part)
		}
	}

	slices.Sort(summaryParts)
	return strings.Join(summaryParts, " | ") + ".", nil
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
