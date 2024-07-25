package normalize

import (
	"net/url"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/pkg/errors"
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
	return purl
}

func PurlOrCpe(component cdx.Component) (string, error) {
	var purl string
	var err error
	if component.PackageURL != "" {
		purl, err = url.PathUnescape(component.PackageURL)
		if err != nil {
			return "", errors.Wrap(err, "could not unescape purl")
		}
	} else if component.CPE != "" {
		purl = component.CPE
	} else if component.Version != "" {
		purl = component.Name + "@" + component.Version
	} else if purl == "" {
		purl = component.Name
	}

	// remove any query parameters
	return purl, nil
}
