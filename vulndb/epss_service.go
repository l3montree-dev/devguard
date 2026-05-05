package vulndb

import (
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
)

type epssService struct {
	cveRepository             shared.CveRepository
	cveRelationshipRepository shared.CVERelationshipRepository
	httpClient                *http.Client
}

var _ shared.EPSService = (*epssService)(nil)

func NewEPSSService(cveRepository shared.CveRepository, cveRelationshipRepository shared.CVERelationshipRepository) epssService {
	return epssService{
		cveRepository:             cveRepository,
		cveRelationshipRepository: cveRelationshipRepository,
		httpClient:                &http.Client{Transport: utils.EgressTransport},
	}
}

var EpssURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

func (s *epssService) Fetch(ctx context.Context) (map[string]dtos.EPSS, error) {
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

	results := make(map[string]dtos.EPSS, 200_000)
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

		results[columns[0]] = dtos.EPSS{
			EPSS:       epss,
			Percentile: percentile,
		}
	}

	return results, nil
}
