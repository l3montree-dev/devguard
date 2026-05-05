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
	"github.com/l3montree-dev/devguard/utils"
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
		httpClient:                &http.Client{Transport: utils.EgressTransport},
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

func (s *cisaKEVService) Fetch(ctx context.Context) ([]models.CVE, error) {
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

// Apply writes pre-fetched CISA KEV entries to the database using the provided transaction,
// expanding KEV data to alias CVEs via the relationship table.
// The caller is responsible for committing or rolling back the transaction.
func (s cisaKEVService) Apply(ctx context.Context, tx shared.DB, cves []models.CVE) error {
	kevMap := make(map[string]models.CVE, len(cves))
	cveIDs := make([]string, len(cves))
	for i, cve := range cves {
		kevMap[cve.CVE] = cve
		cveIDs[i] = cve.CVE
	}

	var relationships []models.CVERelationship
	for i := 0; i < len(cveIDs); i += kevBatchSize {
		end := min(i+kevBatchSize, len(cveIDs))
		batch, err := s.cveRelationshipRepository.GetRelationshipsByTargetCVEBatch(ctx, tx, cveIDs[i:end])
		if err != nil {
			slog.Error("could not fetch CVE relationships", "error", err)
			return err
		}
		relationships = append(relationships, batch...)
	}

	for _, rel := range relationships {
		if kevData, ok := kevMap[rel.TargetCVE]; ok {
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

	for i := 0; i < len(cves); i += kevBatchSize {
		end := min(i+kevBatchSize, len(cves))
		if err := s.cveRepository.UpdateCISAKEVBatch(ctx, tx, cves[i:end]); err != nil {
			slog.Error("error when trying to save CISA KEV information batch")
			return err
		}
	}

	return nil
}

func (s cisaKEVService) Mirror(ctx context.Context) error {
	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	cves, err := s.Fetch(fetchCtx)
	cancel()
	if err != nil {
		slog.Error("could not fetch CISA KEV data", "error", err)
		return err
	}
	tx := s.cveRepository.Begin(ctx)
	defer tx.Rollback()
	if err := s.Apply(ctx, tx, cves); err != nil {
		return err
	}
	return tx.Commit().Error
}
