package vulndb

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"

	"net/http"

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type mitreService struct {
	leaderElector leaderElector
	httpClient    *http.Client
	cweRepository database.Repository[string, CWE, core.DB]
}

func (mitreService) parseCWEs(xmlBytes []byte) ([]*WeaknessType, error) {
	var cweList WeaknessCatalog

	if err := xml.Unmarshal(xmlBytes, &cweList); err != nil {
		return nil, err
	}
	return cweList.Weaknesses.Weakness, nil
}

var cweXMLUrl = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func (mitreService mitreService) fetchCWEXML() ([]*WeaknessType, error) {
	resp, err := mitreService.httpClient.Get(cweXMLUrl)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))

	if err != nil {
		return nil, err
	}

	if len(zipReader.File) == 0 {
		return nil, fmt.Errorf("no files found in zip")
	}

	// get the first file
	file := zipReader.File[0]

	// read the file
	unzippedFileBytes, err := readZipFile(file)
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

func newMitreService(leaderElector leaderElector, cweRepository database.Repository[string, CWE, core.DB]) mitreService {
	return mitreService{
		leaderElector: leaderElector,
		cweRepository: cweRepository,
		httpClient:    &http.Client{},
	}
}

func (mitreService mitreService) mirror() error {
	// parse the CWEs
	cwes, err := mitreService.fetchCWEXML()

	if err != nil {
		return err
	}

	models := make([]CWE, len(cwes))
	// insert the CWEs into the database
	for i, cwe := range cwes {
		models[i] = cwe.toModel()
	}

	return mitreService.cweRepository.SaveBatch(nil, models)
}
