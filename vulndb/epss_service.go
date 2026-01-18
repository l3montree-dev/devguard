package vulndb

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/pkg/errors"
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

const epssBatchSize int = 10_000

func (s epssService) Mirror() (currentErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cves, err := s.fetchCSV(ctx)
	cancel()
	if err != nil {
		slog.Error("could not fetch EPSS data", "error", err)
		return err
	}

	// use a transaction to guarantee atomicity, use defer to handle potential rollbacks
	tx := s.cveRepository.Begin()
	if tx.Error != nil {
		return fmt.Errorf("could not start new transaction: %w", tx.Error)
	}
	defer func() {
		if currentErr != nil {
			rollbackError := tx.Rollback().Error
			if rollbackError != nil {
				slog.Error("could not rollback transaction,there might be a corrupted database state")
			}
		}
	}()

	// process the CVEs in batches to avoid memory problems
	i := 0
	for {
		if i+epssBatchSize < len(cves) {
			err := s.cveRepository.UpdateEpssBatch(tx, cves[i:i+epssBatchSize])
			if err != nil {
				slog.Error("error when trying to save epss information batch")
				return err
			}
			i += epssBatchSize
		} else {
			// not enough cves for a whole batch so we just save the rest
			err := s.cveRepository.UpdateEpssBatch(tx, cves[i:])
			if err != nil {
				slog.Error("error when trying to save epss information batch")
				return err
			}
			break
		}
	}
	return tx.Commit().Error
}
