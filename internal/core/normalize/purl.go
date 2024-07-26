package normalize

import (
	"net/url"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func normalizePurl(purl string) string {
	// unescape the purl
	purl, err := url.PathUnescape(purl)
	if err != nil {
		return purl
	}
	// remove any query parameters
	purl = strings.Split(purl, "?")[0]

	// remove everything follows a "+"
	purl = strings.Split(purl, "+")[0]
	purl = strings.Split(purl, "~")[0]
	return purl
}

func PurlOrCpe(component cdx.Component) string {
	var purl string
	if component.PackageURL != "" {
		return component.PackageURL
	} else if component.CPE != "" {
		purl = component.CPE
	} else if component.Version != "" {
		purl = component.Name + "@" + component.Version
	} else if purl == "" {
		purl = component.Name
	}

	// remove any query parameters
	return purl
}
