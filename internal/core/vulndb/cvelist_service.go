package vulndb

import (
	"archive/zip"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
)

type cvelistService struct {
	httpClient    *http.Client
	cveRepository cveRepository
}

func NewCVEListService(cveRepository cveRepository) cvelistService {
	return cvelistService{
		httpClient:    &http.Client{},
		cveRepository: cveRepository,
	}
}

var cveBaseURL string = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"

func (s *cvelistService) downloadZip() (*zip.Reader, error) {
	req, err := http.NewRequest(http.MethodGet, cveBaseURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not download zip")
	}

	return utils.ZipReaderFromResponse(res)
}

func (s *cvelistService) Mirror() error {
	zipReader, err := s.downloadZip()

	if err != nil {
		slog.Error("could not download zip", "err", err)
		return errors.Wrap(err, "could not download zip")
	}

	if len(zipReader.File) == 0 {
		slog.Error("zip file is empty")
		return errors.New("zip file is empty")
	}

	for _, file := range zipReader.File {
		unzippedFileBytes, err := utils.ReadZipFile(file)
		if err != nil {
			slog.Error("could not read zip file", "err", err)
			continue
		}
		fmt.Println(string(unzippedFileBytes))
	}
	return nil
}
