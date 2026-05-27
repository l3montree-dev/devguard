package transformer

import (
	"fmt"
	"net/url"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
)

func TransformPackagistToDepsDev(
	packagistResponse dtos.PackagistPackageResponse, packageKey string, packageVersion string,
) (dtos.OpenSourceInsightsVersionResponse, error) {
	var out dtos.OpenSourceInsightsVersionResponse

	addLink := func(label, url string) {
		if url == "" {
			return
		}

		out.Links = append(out.Links, struct {
			Label string `json:"label"`
			URL   string `json:"url"`
		}{
			Label: label,
			URL:   url,
		})
	}

	addRelatedProject := func(projectID, relationshipProvenance, relationshipType string) {
		if projectID == "" {
			return
		}

		out.RelatedProjects = append(out.RelatedProjects, struct {
			ProjectKey struct {
				ID string `json:"id"`
			} `json:"projectKey"`
			RelationProvenance string `json:"relationProvenance"`
			RelationType       string `json:"relationType"`
		}{
			ProjectKey: struct {
				ID string `json:"id"`
			}{
				ID: projectID,
			},
			RelationProvenance: relationshipProvenance,
			RelationType:       relationshipType,
		})
	}

	out.AdvisoryKeys = append(out.AdvisoryKeys, packagistResponse.SecurityAdvisories)

	packagistVersions := packagistResponse.Packages[packageKey]

	if len(packagistVersions) < 1 {
		return dtos.OpenSourceInsightsVersionResponse{}, fmt.Errorf("packagist list empty")
	}

	// First package is always the general meta-information package
	pkg := packagistVersions[0]

	out.VersionKey.System = "COMPOSER"
	out.VersionKey.Name = pkg.Name
	out.VersionKey.Version = pkg.Version

	if pkg.Time != "" {
		if t, err := time.Parse(time.RFC3339, pkg.Time); err == nil {
			out.PublishedAt = t
		}
	}

	out.Licenses = append(out.Licenses, pkg.License...)

	out.Registries = []string{
		"https://packagist.org",
	}

	if pkg.Homepage != "" {
		addLink("homepage", pkg.Homepage)
	}

	if pkg.Support != nil {
		addLink("issues", pkg.Support.Issues)
		addLink("source", pkg.Support.Source)
		addLink("docs", pkg.Support.Docs)
		addLink("chat", pkg.Support.Chat)
		addLink("forum", pkg.Support.Forum)
		addLink("wiki", pkg.Support.Wiki)
		addLink("rss", pkg.Support.RSS)
		addLink("security", pkg.Support.Security)
	}

	for dep := range pkg.Require.Map {
		addRelatedProject(dep, "packagist:require", "DEPENDENCY")
	}

	for dep := range pkg.RequireDev.Map {
		addRelatedProject(dep, "packagist:require-dev", "DEV_DEPENDENCY")
	}

	var specificPackage *dtos.PackagistPackageVersion
	if packageVersion != "" {
		for _, specific := range packagistVersions {
			if specific.Version == packageVersion {
				specificPackage = &specific
				break
			}
		}
	}

	if specificPackage == nil {
		return dtos.OpenSourceInsightsVersionResponse{}, fmt.Errorf("no version matching specified package version from packagist")
	}

	if t, err := time.Parse(time.RFC3339, specificPackage.Time); err == nil {
		out.PublishedAt = t
	}

	out.VersionKey.Version = specificPackage.Version

	addLink("source", specificPackage.Source.URL)

	//Create correct projectID that can be used by OpenSourceInsightsVersionResponse and GetProject()
	repositoryURLComponent, err := url.Parse(specificPackage.Source.URL)
	repositoryURL := repositoryURLComponent.Host + repositoryURLComponent.Path
	if err != nil {
		addRelatedProject(specificPackage.Source.URL, "UNVERIFIED_METADATA", "SOURCE_REPO")
	}
	addRelatedProject(repositoryURL, "UNVERIFIED_METADATA", "SOURCE_REPO")
	addLink("distribution", specificPackage.Dist.URL)

	return out, nil
}
