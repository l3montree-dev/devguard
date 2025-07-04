package vuln

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type LicenseRiskService struct {
	licenseRiskRepository core.LicenseRiskRepository
}

func NewLicenseRiskService(licenseRiskReposiory core.LicenseRiskRepository) LicenseRiskService {
	return LicenseRiskService{
		licenseRiskRepository: licenseRiskReposiory,
	}
}

func (service LicenseRiskService) FindLicenseRisksInComponents(components []models.Component) error {

	handledComponents := make(map[string]struct{})
	for _, currentComponent := range components {
		_, found := handledComponents[currentComponent.Purl]
		if !found {
			fmt.Println("")
		}
	}
	return nil
}

func GetOSILicenses() ([]string, error) {
	var validOSILicenses []string
	apiURL := os.Getenv("OSI_LICENSES_API")
	if apiURL == "" {
		return nil, fmt.Errorf("could not get the URL of the OSI API pls check the OSI_LICENSES_API variable in your .env")
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("could not build the http request: %s", err)
	}
	client := http.DefaultClient
	client.Timeout = time.Minute

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http request to %s was unsuccessful (code: %d)", apiURL, resp.StatusCode)
	}
	response := bytes.Buffer{}
	type osiLicense struct {
		ID string `json:"spdx_id"`
	}
	var licenses []osiLicense
	_, err = io.Copy(&response, resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(response.Bytes(), &licenses)
	if err != nil {
		return nil, err
	}

	for _, license := range licenses {
		if license.ID != "" {
			validOSILicenses = append(validOSILicenses, license.ID)
		}
	}

	return validOSILicenses, nil

}
