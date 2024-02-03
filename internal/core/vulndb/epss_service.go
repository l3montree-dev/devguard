package vulndb

import (
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type epssService struct {
	nvdService    NVDService
	cveRepository Repository
	httpClient    *http.Client
}

func newEPSSService(nvdService NVDService, cveRepository Repository) epssService {
	return epssService{
		nvdService:    nvdService,
		cveRepository: cveRepository,
		httpClient:    &http.Client{},
	}
}

var url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

func ptrFloat32(f float32) *float32 {
	return &f
}
func (s *epssService) fetchCSV(ctx context.Context) ([]CVE, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	if err != nil {
		return nil, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	// the body is gzip encoded, so we need to decode it first
	body, err := gzip.NewReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "could not create gzip reader")
	}

	bytes, err := io.ReadAll(body)
	if err != nil {
		return nil, errors.Wrap(err, "could not read body")
	}

	results := make([]CVE, 0)
	// parse the csv - we do not care about the first two lines
	// the first line is information about the model,
	// the second line is the header
	for _, line := range strings.Split(string(bytes), "\n")[2:] {
		columns := strings.Split(line, ",")
		if len(columns) != 3 {
			slog.Warn("could not parse line", "line", line)
			continue
		}
		epss, err := strconv.ParseFloat(columns[1], 32)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse epss")
		}
		percentile, err := strconv.ParseFloat(columns[2], 32)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse percentile")
		}
		results = append(results, CVE{
			CVE:        columns[0],
			EPSS:       ptrFloat32(float32(epss)),
			Percentile: ptrFloat32(float32(percentile)),
		})
	}

	return results, nil
}

func (s epssService) mirror() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cves, err := s.fetchCSV(ctx)
	cancel()
	if err != nil {
		slog.Error("Could not fetch EPSS data", "error", err)
		return err
	} else {
		for _, cve := range cves {
			tmpCVE := cve
			if err := s.cveRepository.GetDB(nil).Model(&CVE{}).Where("cve = ?", tmpCVE.CVE).Updates(map[string]interface{}{
				"epss":       tmpCVE.EPSS,
				"percentile": tmpCVE.Percentile,
			}).Error; err != nil {
				slog.Error("could not save EPSS data", "err", err, "cve", tmpCVE.CVE)
				// just swallow the error
			}
		}
	}
	return nil
}
