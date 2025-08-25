package component

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/licensecheck"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
)

type service struct {
	componentRepository        core.ComponentRepository
	depsDevService             core.DepsDevService
	componentProjectRepository core.ComponentProjectRepository
	licenseRiskService         core.LicenseRiskService
}

func NewComponentService(depsDevService core.DepsDevService, componentProjectRepository core.ComponentProjectRepository, componentRepository core.ComponentRepository, licenseRiskService core.LicenseRiskService) service {
	return service{
		componentRepository:        componentRepository,
		componentProjectRepository: componentProjectRepository,
		depsDevService:             depsDevService,
		licenseRiskService:         licenseRiskService,
	}
}

func combineNamespaceAndName(namespace, name string) string {
	if namespace == "" {
		return name
	}

	return namespace + "/" + name
}

func (s *service) RefreshComponentProjectInformation(project models.ComponentProject) {
	projectKey := project.ProjectKey
	projectResp, err := s.depsDevService.GetProject(context.Background(), projectKey)

	if err != nil {
		slog.Warn("could not get project information", "err", err, "projectKey", projectKey)
		return
	}

	var jsonbScorecard *database.JSONB = nil
	if projectResp.Scorecard != nil {
		jsonb, err := database.JSONbFromStruct(*projectResp.Scorecard)
		if err != nil {
			slog.Warn("could not convert scorecard to jsonb", "err", err)
		} else {
			jsonbScorecard = &jsonb
		}
	}

	// update the project information
	project.StarsCount = projectResp.StarsCount
	project.ForksCount = projectResp.ForksCount
	project.License = projectResp.License
	project.Description = projectResp.Description
	project.Homepage = projectResp.Homepage
	project.ScoreCard = jsonbScorecard

	// save the project
	if err := s.componentProjectRepository.Save(nil, &project); err != nil {
		slog.Warn("could not save project", "err", err)
	} else {
		slog.Info("updated project", "projectKey", projectKey)
		monitoring.DepsDevProjectUpdatedAmount.Inc()
	}
}

func (s *service) GetLicense(component models.Component) (models.Component, error) {
	pURL := component.Purl
	validatedPURL, err := packageurl.FromString(pURL)
	if err != nil {
		// swallow the error
		component.License = utils.Ptr("unknown")
		return component, nil
	}

	// check whether its a debian package. If it is we get our information from the debian package master
	switch validatedPURL.Type {
	case "deb":
		packageInformation, err := getDebianPackageInformation(validatedPURL)
		if err != nil {
			// swallow error but display a warning
			slog.Warn("could not get license information", "err", err, "purl", pURL)
			component.License = utils.Ptr("unknown")
			return component, nil
		}

		cov := licensecheck.Scan(packageInformation.Bytes())
		if len(cov.Match) == 0 {
			component.License = utils.Ptr("unknown")
			return component, nil
		}
		component.License = &cov.Match[0].ID
	case "apk":
		license, err := getAlpineLicense(validatedPURL)
		if err != nil || license == "" {
			component.License = utils.Ptr("unknown")
			return component, err
		}
		component.License = &license
	default:
		resp, err := s.depsDevService.GetVersion(context.Background(), validatedPURL.Type, combineNamespaceAndName(validatedPURL.Namespace, validatedPURL.Name), validatedPURL.Version)

		if err != nil {
			slog.Warn("could not get license information", "err", err, "purl", pURL)

			// set the license to unknown
			component.License = utils.Ptr("unknown")
			return component, nil
		}

		// check if there is a license
		if len(resp.Licenses) > 0 {
			// update the license
			component.License = &resp.Licenses[0]
			component.Published = &resp.PublishedAt
		} else {
			// set the license to unknown
			component.License = utils.Ptr("unknown")
		}

		// check if there is a related project
		if len(resp.RelatedProjects) == 0 {
			slog.Warn("no related projects found", "purl", pURL)
			return component, nil
		}

		// find the project with the "SOURCE_REPO" type
		for _, project := range resp.RelatedProjects {
			if project.RelationType == "SOURCE_REPO" {
				// get the project key and fetch the project
				projectKey := project.ProjectKey.ID

				// fetch the project
				projectResp, err := s.depsDevService.GetProject(context.Background(), projectKey)
				if err != nil {
					slog.Warn("could not get project information", "err", err, "projectKey", projectKey)
				}

				var jsonbScorecard *database.JSONB = nil
				var scoreCardScore *float64 = nil
				if projectResp.Scorecard != nil {
					jsonb, err := database.JSONbFromStruct(*projectResp.Scorecard)
					scoreCardScore = &projectResp.Scorecard.OverallScore

					if err != nil {
						slog.Warn("could not convert scorecard to jsonb", "err", err)
					} else {
						jsonbScorecard = &jsonb
					}
				}
				// save the project information
				componentProject := &models.ComponentProject{
					ProjectKey:     projectKey,
					StarsCount:     projectResp.StarsCount,
					ForksCount:     projectResp.ForksCount,
					License:        projectResp.License,
					Description:    projectResp.Description,
					Homepage:       projectResp.Homepage,
					ScoreCard:      jsonbScorecard,
					ScoreCardScore: scoreCardScore,
				}

				component.ComponentProject = componentProject
				component.ComponentProjectKey = &projectKey
				break
			}
		}
	}
	return component, nil
}

func (s *service) GetAndSaveLicenseInformation(assetVersion models.AssetVersion, scannerID string) ([]models.Component, error) {
	componentDependencies, err := s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		return nil, err
	}

	// only get the components - there might be duplicates
	componentsWithoutLicense := make([]models.Component, 0)
	seen := make(map[string]bool)
	for _, componentDependency := range componentDependencies {
		if _, ok := seen[componentDependency.DependencyPurl]; !ok && componentDependency.Dependency.License == nil {
			seen[componentDependency.DependencyPurl] = true
			componentsWithoutLicense = append(componentsWithoutLicense, componentDependency.Dependency)
		}
	}

	//why are we only getting new licenses and not updating existing ones? - licenses shouldn't change after once they are set
	slog.Info("getting license information for components", "amount", len(componentsWithoutLicense))
	errGroup := utils.ErrGroup[models.Component](10)
	for _, component := range componentsWithoutLicense {
		errGroup.Go(func() (models.Component, error) {
			return s.GetLicense(component)
		})
	}

	// wait for all components to be processed
	components, err := errGroup.WaitAndCollect()
	if err != nil {
		return nil, err
	}

	// save the components
	if err := s.componentRepository.SaveBatch(nil, components); err != nil {
		return nil, err
	}

	allComponents := components
	// get all the components - with licenses and without
	for _, componentDependency := range componentDependencies {
		if !seen[componentDependency.DependencyPurl] {
			// if the component is not in the seen map, it means it was not processed to get a new license
			allComponents = append(allComponents, componentDependency.Dependency)
		}
	}

	// find potential license risks
	err = s.licenseRiskService.FindLicenseRisksInComponents(assetVersion, allComponents, scannerID)
	if err != nil {
		return nil, err
	}

	return allComponents, nil
}

// RefreshAllLicenses forces re-fetching license information for all components of an asset version
func (s *service) RefreshAllLicenses(assetVersion models.AssetVersion, scannerID string) ([]models.Component, error) {
	componentDependencies, err := s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		return nil, err
	}

	// collect unique components
	componentsMap := make(map[string]models.Component)
	for _, cd := range componentDependencies {
		componentsMap[cd.DependencyPurl] = cd.Dependency
	}

	components := make([]models.Component, 0, len(componentsMap))
	for _, c := range componentsMap {
		// clear existing license so GetLicense will re-fetch
		c.License = nil
		components = append(components, c)
	}

	slog.Info("refreshing license information for components", "amount", len(components))

	errGroup := utils.ErrGroup[models.Component](10)
	for _, component := range components {
		comp := component
		errGroup.Go(func() (models.Component, error) {
			return s.GetLicense(comp)
		})
	}

	updatedComponents, err := errGroup.WaitAndCollect()
	if err != nil {
		return nil, err
	}

	if err := s.componentRepository.SaveBatch(nil, updatedComponents); err != nil {
		return nil, err
	}

	// find potential license risks for all components
	err = s.licenseRiskService.FindLicenseRisksInComponents(assetVersion, updatedComponents, scannerID)
	if err != nil {
		return nil, err
	}

	return updatedComponents, nil
}

func getDebianPackageInformation(pURL packageurl.PackageURL) (*bytes.Buffer, error) {
	buff := bytes.Buffer{}

	requestURL := fmt.Sprintf("https://metadata.ftp-master.debian.org/changelogs/main/%c/%s/%s_%s_copyright", pURL.Name[0], pURL.Name, pURL.Name, pURL.Version)
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not get debian package information: %s", resp.Status)
	}

	defer resp.Body.Close()
	_, err = io.Copy(&buff, resp.Body)
	return &buff, err
}

var (
	alpineReleaseVersions []string
	alpineVersionIndex                      = 0
	alpineLicenseMap      map[string]string = make(map[string]string, 8192) // Map to cache alpine type licenses. Form : <package name> + <package version> -> license (size is just an approximate)
	alpineMutex           sync.Mutex                                        // since we are running in a go routine we need to sync the access to the map
)

func getAlpineLicense(pURL packageurl.PackageURL) (string, error) {
	var license string
	alpineMutex.Lock() // it seems we cannot parallelize anything in this function, only 1 thread should get the versions at a time
	// and only 1 thread should get new license information at a time
	// because other threads may be included in the information currently fetched by the other thread
	defer alpineMutex.Unlock()
	if len(alpineReleaseVersions) == 0 {
		err := retrieveAlpineVersions()
		if err != nil {
			return license, err
		}
	}
	//if there is already a thread which gets new set of license information we should wait for that thread to finish before checking
	license, exists := alpineLicenseMap[pURL.Name+pURL.Version]
	if exists {
		return license, nil
	}
	for alpineVersionIndex < len(alpineReleaseVersions) {

		alpineBaseURL := os.Getenv("ALPINE_LICENSE_API")
		if alpineBaseURL == "" {
			return license, fmt.Errorf("missing ALPINE_RELEASES_API environment variable, see .env.example for an example value")
		}
		versionURL := fmt.Sprintf("%s%s/main/x86_64/APKINDEX.tar.gz", alpineBaseURL, alpineReleaseVersions[alpineVersionIndex])
		alpineVersionIndex++

		// maybe operate on a queue/stack not with indexes. If requests fails on the way it will never be retrieved again
		apkIndex, err := getAPKIndexInformation(versionURL)
		if err != nil {
			return license, err
		}
		extractLicensesFromAPKINDEX(*apkIndex)
		license, exists = alpineLicenseMap[pURL.Name+pURL.Version]
		if exists {
			return license, nil
		}
	}
	slog.Warn("alpine license not found for", pURL.String(), "")
	return license, nil
}

func getAPKIndexInformation(url string) (*bytes.Buffer, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &bytes.Buffer{}, err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return &bytes.Buffer{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return &bytes.Buffer{}, fmt.Errorf("http request was unsuccessful, status code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	buf := bytes.Buffer{}
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return &bytes.Buffer{}, err
	}

	unzippedContents, err := gzip.NewReader(&buf)
	if err != nil {
		return &bytes.Buffer{}, err
	}
	defer unzippedContents.Close()

	tarContents := tar.NewReader(unzippedContents)
	apkIndex := bytes.NewBuffer(make([]byte, 0, 2*1000*1000)) // allocate 2 MB memory for buf to avoid resizing operations
	for {                                                     //go through every file
		header, err := tarContents.Next()
		if err == io.EOF {
			break // end of tar archive
		}
		if err != nil {
			log.Fatal(err)
		}
		if header.Name == "APKINDEX" {
			_, err = apkIndex.ReadFrom(tarContents)
			if err != nil {
				return &bytes.Buffer{}, err
			}
		}
	}
	return apkIndex, nil
}

// splits contents into blocks separated by two new line characters. Then iterate over every block to extract package name, version and license using string modifications
func extractLicensesFromAPKINDEX(contents bytes.Buffer) {
	var name, version, license string
	var indexName, indexVersion, indexLicense int
	for pkg := range strings.SplitSeq(contents.String(), "\n\n") {
		indexName = strings.Index(pkg, "\nP:")
		if indexName != -1 { // first check package name
			name, _, _ = strings.Cut(pkg[indexName+3:], "\n")
			indexVersion = strings.Index(pkg[indexName+len(name):], "\nV:") // reduce operations by starting the search after the package field
			if indexVersion != -1 {                                         // then check version
				version, _, _ = strings.Cut(pkg[indexName+len(name)+indexVersion+3:], "\n")
				indexLicense = strings.Index(pkg[indexName+len(name)+indexVersion+len(version):], "\nL:")
				if indexLicense != -1 { // last check the license
					license, _, _ = strings.Cut(pkg[indexName+len(name)+indexVersion+len(version)+indexLicense+3:], "\n") // reduce operations by starting the search after the version field
					alpineLicenseMap[name+version] = license
				}
			}
		}
	}
}

func retrieveAlpineVersions() error {
	buf := bytes.NewBuffer(make([]byte, 0, 64*1000)) // json size is roughly 64 KB
	releasesURL := os.Getenv("ALPINE_RELEASES_API")
	if releasesURL == "" {
		return fmt.Errorf("missing ALPINE_RELEASES_API environment variable, see .env.example for an example value")
	}
	req, err := http.NewRequest("GET", releasesURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return err
	}

	type releases struct {
		ReleaseBranches []struct {
			Branch string `json:"rel_branch"`
		} `json:"release_branches"`
	}
	r := releases{}
	err = json.Unmarshal(buf.Bytes(), &r)
	if err != nil {
		return err
	}
	alpineReleaseVersions = make([]string, 0, len(r.ReleaseBranches))
	for _, rls := range r.ReleaseBranches {
		if rls.Branch[1] == '3' || rls.Branch == "edge" { //only check versions 3.x and edge
			alpineReleaseVersions = append(alpineReleaseVersions, rls.Branch)
		}
	}
	fmt.Printf("\n\nThis is the list of versions: %v\n\n", alpineReleaseVersions)
	return nil
}
