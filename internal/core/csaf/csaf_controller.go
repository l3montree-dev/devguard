package csaf

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/l3montree-dev/devguard/internal/constants"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

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

	publicKeyPath := os.Getenv("OPENPGP_PUBLIC_KEY_PATH")
	if publicKeyPath == "" {
		publicKeyPath = "csaf-openpgp-public-key.asc"
	}

	publicKeyData, err := os.ReadFile(publicKeyPath)
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

	return ctx.JSONPretty(200, aggregator, constants.PrettyJSONIndent)
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
			DirectoryURL: fmt.Sprintf("%s/api/v1/organizations/%s/projects/%s/assets/%s/csaf/white", hostURL, org.Slug, asset.Project.Slug, asset.Slug),
		}
		distributions = append(distributions, distribution)
	}
	metadata.Distributions = distributions

	return ctx.JSONPretty(200, metadata, constants.PrettyJSONIndent)
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
		return ctx.JSONPretty(200, csafReport, constants.PrettyJSONIndent)
	case "asc":
		// return the signature of the json encoding of the report
		buf := bytes.Buffer{}
		encoder := json.NewEncoder(&buf)
		encoder.SetIndent("", constants.PrettyJSONIndent)
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
		encoder.SetIndent("", constants.PrettyJSONIndent)
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
		encoder.SetIndent("", constants.PrettyJSONIndent)
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
