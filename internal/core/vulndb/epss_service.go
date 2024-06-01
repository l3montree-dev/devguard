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

	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

type epssService struct {
	nvdService    NVDService
	cveRepository cveRepository
	httpClient    *http.Client
}

func NewEPSSService(nvdService NVDService, cveRepository cveRepository) epssService {
	return epssService{
		nvdService:    nvdService,
		cveRepository: cveRepository,
		httpClient:    &http.Client{},
	}
}

var epssURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

func ptrFloat32(f float32) *float32 {
	return &f
}
func (s *epssService) fetchCSV(ctx context.Context) ([]models.CVE, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, epssURL, nil)

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

	results := make([]models.CVE, 0)
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
		results = append(results, models.CVE{
			CVE:        columns[0],
			EPSS:       ptrFloat32(float32(epss)),
			Percentile: ptrFloat32(float32(percentile)),
		})
	}

	return results, nil
}

func (s epssService) Mirror() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cves, err := s.fetchCSV(ctx)
	cancel()

	group := errgroup.Group{}
	group.SetLimit(10) // 10 because, i do not really know.
	if err != nil {
		slog.Error("Could not fetch EPSS data", "error", err)
		return err
	} else {
		for _, cve := range cves {
			tmpCVE := cve
			group.Go(
				func() error {
					if err := s.cveRepository.GetDB(nil).Model(&models.CVE{}).Where("cve = ?", tmpCVE.CVE).Updates(map[string]interface{}{
						"epss":       tmpCVE.EPSS,
						"percentile": tmpCVE.Percentile,
					}).Error; err != nil {
						slog.Error("could not save EPSS data", "err", err, "cve", tmpCVE.CVE)
						// just swallow the error
					}
					return nil
				},
			)

		}
	}
	return group.Wait()
}
