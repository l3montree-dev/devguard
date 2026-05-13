package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
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

	slog.Info("updating CISA KEV data", "direct", len(cveIDs), "viaRelationships", len(cves)-len(cveIDs))

	for i := 0; i < len(cves); i += kevBatchSize {
		end := min(i+kevBatchSize, len(cves))
		if err := s.cveRepository.UpdateCISAKEVBatch(ctx, tx, cves[i:end]); err != nil {
			slog.Error("error when trying to save CISA KEV information batch")
			return err
		}
	}

	return nil
}

func insertCISAKEVBulk(ctx context.Context, tx pgx.Tx, entries []CISAKEVEntry) error {
	if len(entries) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE IF NOT EXISTS kev_stage (
			cve                     text,
			cisa_exploit_add        date,
			cisa_action_due         date,
			cisa_required_action    text,
			cisa_vulnerability_name text
		) ON COMMIT DROP`); err != nil {
		return fmt.Errorf("could not create kev staging table: %w", err)
	}

	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"kev_stage"},
		[]string{"cve", "cisa_exploit_add", "cisa_action_due", "cisa_required_action", "cisa_vulnerability_name"},
		pgx.CopyFromSlice(len(entries), func(i int) ([]any, error) {
			e := entries[i]
			return []any{e.CVE, e.ExploitAddDate, e.ActionDueDate, e.RequiredAction, e.VulnerabilityName}, nil
		})); err != nil {
		return fmt.Errorf("could not copy kev rows into staging table: %w", err)
	}

	// Reset all CISA KEV fields before re-applying so CVEs that fell off the catalog are cleared.
	if _, err := tx.Exec(ctx, `UPDATE cves SET cisa_exploit_add = NULL, cisa_action_due = NULL, cisa_required_action = NULL, cisa_vulnerability_name = NULL`); err != nil {
		return fmt.Errorf("could not reset cisa kev fields: %w", err)
	}

	// Update direct CVEs and alias CVEs. DISTINCT ON with ORDER BY cisa_exploit_add ASC gives a
	// deterministic winner when an alias maps to multiple KEV canonical CVEs.
	tag, err := tx.Exec(ctx, `
		UPDATE cves SET
			cisa_exploit_add        = ks.cisa_exploit_add,
			cisa_action_due         = ks.cisa_action_due,
			cisa_required_action    = ks.cisa_required_action,
			cisa_vulnerability_name = ks.cisa_vulnerability_name
		FROM (
			SELECT DISTINCT ON (cve) cve, cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name
			FROM (
				SELECT cve, cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name
				FROM kev_stage
				UNION ALL
				SELECT cr.source_cve, ks.cisa_exploit_add, ks.cisa_action_due, ks.cisa_required_action, ks.cisa_vulnerability_name
				FROM kev_stage ks
				JOIN cve_relationships cr ON cr.target_cve = ks.cve
			) combined
			ORDER BY cve, cisa_exploit_add ASC, cisa_vulnerability_name ASC
		) ks
		WHERE cves.cve = ks.cve`)
	if err != nil {
		return fmt.Errorf("could not update cves with kev data: %w", err)
	}
	slog.Debug("insertCISAKEVBulk: update complete", "rows_updated", tag.RowsAffected())
	return nil
}

func applyCISAKEVToStage(ctx context.Context, tx pgx.Tx, entries []CISAKEVEntry) error {
	if len(entries) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE IF NOT EXISTS kev_stage (
			cve                     text,
			cisa_exploit_add        date,
			cisa_action_due         date,
			cisa_required_action    text,
			cisa_vulnerability_name text
		) ON COMMIT DROP`); err != nil {
		return fmt.Errorf("could not create kev staging table: %w", err)
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"kev_stage"},
		[]string{"cve", "cisa_exploit_add", "cisa_action_due", "cisa_required_action", "cisa_vulnerability_name"},
		pgx.CopyFromSlice(len(entries), func(i int) ([]any, error) {
			e := entries[i]
			return []any{e.CVE, e.ExploitAddDate, e.ActionDueDate, e.RequiredAction, e.VulnerabilityName}, nil
		})); err != nil {
		return fmt.Errorf("could not copy kev rows into kev staging table: %w", err)
	}

	tag, err := tx.Exec(ctx, `
		UPDATE cves_stage SET
			cisa_exploit_add        = ks.cisa_exploit_add,
			cisa_action_due         = ks.cisa_action_due,
			cisa_required_action    = ks.cisa_required_action,
			cisa_vulnerability_name = ks.cisa_vulnerability_name
		FROM (
			SELECT DISTINCT ON (cve) cve, cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name
			FROM (
				SELECT cve, cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name
				FROM kev_stage
				UNION ALL
				SELECT cr.source_cve, ks.cisa_exploit_add, ks.cisa_action_due, ks.cisa_required_action, ks.cisa_vulnerability_name
				FROM kev_stage ks
				JOIN cve_relationships cr ON cr.target_cve = ks.cve
			) combined
			ORDER BY cve, cisa_exploit_add ASC, cisa_vulnerability_name ASC
		) ks
		WHERE cves_stage.cve = ks.cve`)
	if err != nil {
		return fmt.Errorf("could not update cves_stage with kev data: %w", err)
	}
	slog.Debug("applyCISAKEVToStage: update complete", "rows_updated", tag.RowsAffected())
	return nil
}
