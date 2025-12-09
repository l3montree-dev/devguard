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

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

type epssService struct {
	cveRepository shared.CveRepository
	httpClient    *http.Client
}

func NewEPSSService(cveRepository shared.CveRepository) epssService {
	return epssService{
		cveRepository: cveRepository,
		httpClient:    &http.Client{},
	}
}

var epssURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

func ptrFloat32(f float32) *float32 {
	return &f
}
func ptrFloat64(f float64) *float64 {
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
			EPSS:       ptrFloat64(float64(epss)),
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
		start := time.Now()
		for i, cve := range cves {
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
			if i > 0 && i%1000 == 0 {
				slog.Info("Processed CVEs", "amount", i, "duration", time.Since(start))
			}
		}
	}
	return group.Wait()
}
