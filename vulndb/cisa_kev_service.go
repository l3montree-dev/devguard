package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/datatypes"
)

type cisaKEVService struct {
	cveRepository             shared.CveRepository
	cveRelationshipRepository shared.CVERelationshipRepository
	httpClient                *http.Client
}

func NewCISAKEVService(cveRepository shared.CveRepository, cveRelationshipRepository shared.CVERelationshipRepository) cisaKEVService {
	return cisaKEVService{
		cveRepository:             cveRepository,
		cveRelationshipRepository: cveRelationshipRepository,
		httpClient:                &http.Client{},
	}
}

var CisaKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type cisaKEVCatalog struct {
	Title           string         `json:"title"`
	CatalogVersion  string         `json:"catalogVersion"`
	DateReleased    string         `json:"dateReleased"`
	Count           int            `json:"count"`
	Vulnerabilities []cisaKEVEntry `json:"vulnerabilities"`
}

type cisaKEVEntry struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

const kevBatchSize int = 50_000

func (s *cisaKEVService) fetchJSON(ctx context.Context) ([]models.CVE, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, CisaKEVURL, nil)
	if err != nil {
		return nil, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %w", err)
	}

	var catalog cisaKEVCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("could not parse JSON: %w", err)
	}

	results := make([]models.CVE, 0, len(catalog.Vulnerabilities))
	for _, entry := range catalog.Vulnerabilities {
		dateAdded, err := parseDate(entry.DateAdded)
		if err != nil {
			slog.Warn("could not parse dateAdded", "cve", entry.CVEID, "date", entry.DateAdded)
			continue
		}

		dueDate, err := parseDate(entry.DueDate)
		if err != nil {
			slog.Warn("could not parse dueDate", "cve", entry.CVEID, "date", entry.DueDate)
			continue
		}

		results = append(results, models.CVE{
			CVE:                   entry.CVEID,
			CISAExploitAdd:        dateAdded,
			CISAActionDue:         dueDate,
			CISARequiredAction:    entry.RequiredAction,
			CISAVulnerabilityName: entry.VulnerabilityName,
		})
	}

	return results, nil
}

func parseDate(dateStr string) (*datatypes.Date, error) {
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return nil, err
	}
	d := datatypes.Date(t)
	return &d, nil
}

func (s cisaKEVService) Mirror() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cves, err := s.fetchJSON(ctx)
	cancel()
	if err != nil {
		slog.Error("could not fetch CISA KEV data", "error", err)
		return err
	}

	tx := s.cveRepository.Begin()

	// build a map of CVE ID -> KEV data for quick lookup
	kevMap := make(map[string]models.CVE, len(cves))
	cveIDs := make([]string, len(cves))
	for i, cve := range cves {
		kevMap[cve.CVE] = cve
		cveIDs[i] = cve.CVE
	}

	// query relationships where target_cve matches any of our CVE IDs
	// this allows us to propagate KEV data to related CVEs (e.g., GHSA -> CVE aliases)
	// process in batches to avoid PostgreSQL parameter limit
	var relationships []models.CVERelationship
	for i := 0; i < len(cveIDs); i += kevBatchSize {
		end := min(i+kevBatchSize, len(cveIDs))
		batch, err := s.cveRelationshipRepository.GetRelationshipsByTargetCVEBatch(tx, cveIDs[i:end])
		if err != nil {
			slog.Error("could not fetch CVE relationships", "error", err)
			return err
		}
		relationships = append(relationships, batch...)
	}

	// expand CVE list with related source CVEs that should inherit KEV data
	for _, rel := range relationships {
		if kevData, ok := kevMap[rel.TargetCVE]; ok {
			// only add if not already in the map to avoid duplicates
			if _, exists := kevMap[rel.SourceCVE]; !exists {
				relatedCVE := models.CVE{
					CVE:                   rel.SourceCVE,
					CISAExploitAdd:        kevData.CISAExploitAdd,
					CISAActionDue:         kevData.CISAActionDue,
					CISARequiredAction:    kevData.CISARequiredAction,
					CISAVulnerabilityName: kevData.CISAVulnerabilityName,
				}
				cves = append(cves, relatedCVE)
				kevMap[rel.SourceCVE] = relatedCVE
			}
		}
	}

	slog.Info("updating CISA KEV data", "direct", len(cveIDs), "via_relationships", len(cves)-len(cveIDs))

	// process the CVEs in batches
	for i := 0; i < len(cves); i += kevBatchSize {
		end := min(i+kevBatchSize, len(cves))
		err := s.cveRepository.UpdateCISAKEVBatch(tx, cves[i:end])
		if err != nil {
			slog.Error("error when trying to save CISA KEV information batch")
			return err
		}
	}

	return tx.Commit().Error
}
