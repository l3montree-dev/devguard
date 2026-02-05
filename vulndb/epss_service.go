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
)

type epssService struct {
	cveRepository             shared.CveRepository
	cveRelationshipRepository shared.CVERelationshipRepository
	httpClient                *http.Client
}

func NewEPSSService(cveRepository shared.CveRepository, cveRelationshipRepository shared.CVERelationshipRepository) epssService {
	return epssService{
		cveRepository:             cveRepository,
		cveRelationshipRepository: cveRelationshipRepository,
		httpClient:                &http.Client{},
	}
}

var EpssURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

func ptrFloat32(f float32) *float32 {
	return &f
}
func ptrFloat64(f float64) *float64 {
	return &f
}
func (s *epssService) fetchCSV(ctx context.Context) ([]models.CVE, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, EpssURL, nil)

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

const epssBatchSize int = 50_000

func (s epssService) Mirror() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cves, err := s.fetchCSV(ctx)
	cancel()
	if err != nil {
		slog.Error("could not fetch EPSS data", "error", err)
		return err
	}

	// use a transaction to guarantee atomicity, use defer to handle potential rollbacks
	tx := s.cveRepository.Begin()

	// build a map of CVE ID -> EPSS data for quick lookup
	epssMap := make(map[string]models.CVE, len(cves))
	cveIDs := make([]string, len(cves))
	for i, cve := range cves {
		epssMap[cve.CVE] = cve
		cveIDs[i] = cve.CVE
	}

	// query relationships where target_cve matches any of our CVE IDs
	// this allows us to propagate EPSS scores to related CVEs (e.g., GHSA -> CVE aliases)
	// process in batches to avoid PostgreSQL parameter limit
	var relationships []models.CVERelationship
	for i := 0; i < len(cveIDs); i += epssBatchSize {
		end := min(i+epssBatchSize, len(cveIDs))
		batch, err := s.cveRelationshipRepository.GetRelationshipsByTargetCVEBatch(tx, cveIDs[i:end])
		if err != nil {
			slog.Error("could not fetch CVE relationships", "error", err)
			return err
		}
		relationships = append(relationships, batch...)
	}

	// expand CVE list with related source CVEs that should inherit EPSS scores
	for _, rel := range relationships {
		if epssData, ok := epssMap[rel.TargetCVE]; ok {
			// only add if not already in the map to avoid duplicates
			if _, exists := epssMap[rel.SourceCVE]; !exists {
				relatedCVE := models.CVE{
					CVE:        rel.SourceCVE,
					EPSS:       epssData.EPSS,
					Percentile: epssData.Percentile,
				}
				cves = append(cves, relatedCVE)
				epssMap[rel.SourceCVE] = relatedCVE
			}
		}
	}

	slog.Info("updating EPSS scores", "direct", len(cveIDs), "via_relationships", len(cves)-len(cveIDs))

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
