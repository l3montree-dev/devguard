package vulndb

import (
	"encoding/xml"
	"fmt"

	"net/http"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

type mitreService struct {
	httpClient    *http.Client
	cweRepository shared.CweRepository
}

func (mitreService) parseCWEs(xmlBytes []byte) ([]*WeaknessType, error) {
	var cweList WeaknessCatalog

	if err := xml.Unmarshal(xmlBytes, &cweList); err != nil {
		return nil, err
	}
	return cweList.Weaknesses.Weakness, nil
}

var cweXMLURL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

func (mitreService mitreService) fetchCWEXML() ([]*WeaknessType, error) {
	resp, err := mitreService.httpClient.Get(cweXMLURL)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	zipReader, err := utils.ZipReaderFromResponse(resp)
	if err != nil {
		return nil, err
	}

	if len(zipReader.File) == 0 {
		return nil, fmt.Errorf("no files found in zip")
	}

	// get the first file
	file := zipReader.File[0]

	// read the file
	unzippedFileBytes, err := utils.ReadZipFile(file)
	if err != nil {
		return nil, err
	}

	// parse the file
	cwes, err := mitreService.parseCWEs(unzippedFileBytes)
	if err != nil {
		return nil, err
	}

	return cwes, nil
}

func NewMitreService(cweRepository shared.CweRepository) mitreService {
	return mitreService{
		cweRepository: cweRepository,
		httpClient:    &http.Client{},
	}
}

func (mitreService mitreService) Mirror() error {
	// parse the CWEs
	cwes, err := mitreService.fetchCWEXML()

	if err != nil {
		return err
	}

	models := make([]models.CWE, len(cwes))
	// insert the CWEs into the database
	for i, cwe := range cwes {
		models[i] = cwe.toModel()
	}

	return mitreService.cweRepository.SaveBatch(nil, models)
}
