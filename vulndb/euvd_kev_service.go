package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

type euvdKEVService struct {
	cveRepository             shared.CveRepository
	cveRelationshipRepository shared.CVERelationshipRepository
}

func NewEUVDKEVService(cveRepository shared.CveRepository, cveRelationshipRepository shared.CVERelationshipRepository) euvdKEVService {
	return euvdKEVService{
		cveRepository:             cveRepository,
		cveRelationshipRepository: cveRelationshipRepository,
	}
}

var euvdKEVURL = "https://euvdservices.enisa.europa.eu/api/kev/dump"

const (
	euvdSourceID = "eukev_kev"
	cisaSourceID = "cisa_kev"
)

type euvdKEVEntry struct {
	CVEID     string   `json:"cveId"`
	EUVDID    string   `json:"euvdId"`
	DateAdded string   `json:"dateAdded"`
	Sources   []string `json:"sources"`
}

func (service euvdKEVService) Fetch(ctx context.Context) ([]models.CVE, error) {
	body, err := utils.DoGetRequestWithContext(ctx, euvdKEVURL, &utils.EgressClient)
	if err != nil {
		return nil, fmt.Errorf("could not fetch euvd KEV information: %w", err)
	}
	defer body.Close()

	var euvdKEV []euvdKEVEntry
	if err := json.NewDecoder(body).Decode(&euvdKEV); err != nil {
		return nil, fmt.Errorf("could not parse JSON: %w", err)
	}

	results := make([]models.CVE, 0, len(euvdKEV))
	for _, entry := range euvdKEV {
		if len(entry.Sources) == 0 {
			continue
		}
		dateAdded, err := parseDate(entry.DateAdded)
		if err != nil {
			slog.Warn("could not parse dateAdded", "cve", entry.CVEID, "date", entry.DateAdded)
			continue
		}

		cve := models.CVE{
			CVE: entry.CVEID,
		}

		// add exploit add information based on which source(s) are listed
		for _, sourceID := range entry.Sources {
			switch sourceID {
			case euvdSourceID:
				cve.EUVDExploitAdd = dateAdded
			case cisaSourceID:
				cve.CISAExploitAdd = dateAdded
			default:
				// if the schema changes it should break to force investigation of the schema
				return nil, fmt.Errorf("unexpected identifier found in EUVD KEV. CVE-ID: %s, sourceID: %s ", entry.CVEID, sourceID)
			}
		}

		results = append(results, cve)
	}

	return results, nil
}
