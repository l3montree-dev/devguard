package vulndb

import (
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

const (
	euvdIDAliasURL  = "https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping" // URL to fetch the alias mapping from EUVD-IDs to CVE-IDs
	csvEUVDColumnID = "euvd_id"                                                        // name of the csv columns, should be stable over all versions;if it changes it should break
	csvCVEColumnID  = "cve_id"
)

type euvdService struct {
	cveRepository             shared.CveRepository
	cveRelationshipRepository shared.CVERelationshipRepository
	pool                      *pgxpool.Pool
	httpClient                *http.Client
}

func NewEUVDService(cveRepository shared.CveRepository, cveRelationshipRepository shared.CVERelationshipRepository, pool *pgxpool.Pool) euvdService {
	return euvdService{
		cveRepository:             cveRepository,
		cveRelationshipRepository: cveRelationshipRepository,
		pool:                      pool,
		httpClient:                &http.Client{Transport: utils.EgressTransport},
	}
}

func (service euvdService) importEUVDAliases(ctx context.Context, tx pgx.Tx) ([]models.CVERelationship, error) {
	aliasCSV, err := service.fetchEUVDAliases()
	if err != nil {
		return nil, err
	}

	relationships, err := service.convertAliasesToRelationships(aliasCSV)
	if err != nil {
		return nil, err
	}
	return service.ResolveAndInsertEUVDRelationships(ctx, tx, relationships)
}

// after fetching the CVE aliases of the EUVD we want to resolve those 'original' CVEs to their downstream relations
// for CVEs with no downstream alias we only keep them if they exist in the cves so the fk on source_cve holds
func (service euvdService) ResolveAndInsertEUVDRelationships(ctx context.Context, tx pgx.Tx, relationships []models.CVERelationship) ([]models.CVERelationship, error) {
	euvdStageTable := "euvd_relationships_stage"

	start := time.Now()
	slog.Info("start resolving and inserting euvd relationships into cve_relationships")
	if _, err := tx.Exec(ctx, fmt.Sprintf(`CREATE TEMP TABLE %s (LIKE cve_relationships) ON COMMIT DROP`, euvdStageTable)); err != nil {
		return nil, fmt.Errorf("could not create euvd stage table: %w", err)
	}

	if err := InsertCVERelationshipsBulk(ctx, tx, relationships, euvdStageTable); err != nil {
		return nil, fmt.Errorf("could not insert euvd relationships bulk: %w", err)
	}

	rows, err := tx.Query(ctx, `
	INSERT INTO cve_relationships (target_cve, source_cve, relationship_type)
	-- first resolve the euvd relations via a join to the downstream relations
	SELECT euvd.source_cve AS target_cve, cr.source_cve, cr.relationship_type
	FROM cve_relationships cr
	JOIN euvd_relationships_stage euvd ON euvd.target_cve = cr.target_cve
	UNION
	-- then combine them with all cves that do not have a relationship but are present in the cves table
	SELECT euvd.source_cve AS target_cve, euvd.target_cve AS source_cve, 'euvd' AS relationship_type
	FROM euvd_relationships_stage euvd
	WHERE NOT EXISTS (SELECT 1 FROM cve_relationships cr WHERE cr.target_cve = euvd.target_cve)
	AND EXISTS (SELECT 1 FROM cves c WHERE c.cve = euvd.target_cve)
	ON CONFLICT (target_cve, source_cve, relationship_type) DO NOTHING
	-- return the resolved rows to be written in the exported gob files
	RETURNING target_cve, source_cve, relationship_type`)
	if err != nil {
		return nil, fmt.Errorf("could not resolve and insert euvd relationships: %w", err)
	}
	defer rows.Close()
	slog.Info("finished inserting euvd relationships", "took", time.Since(start))

	// convert rows into cveRelationships model
	resolved := make([]models.CVERelationship, 0, len(relationships))
	for rows.Next() {
		var relation models.CVERelationship
		if err := rows.Scan(&relation.TargetCVE, &relation.SourceCVE, &relation.RelationshipType); err != nil {
			return nil, fmt.Errorf("could not scan resolved euvd relationship: %w", err)
		}
		resolved = append(resolved, relation)
	}
	return resolved, rows.Err()
}

func (service euvdService) fetchEUVDAliases() ([][]string, error) {
	body, err := utils.DoGetRequestWithContext(context.Background(), euvdIDAliasURL, nil)
	if err != nil {
		return nil, fmt.Errorf("could not fetch euvd aliases: %w", err)
	}
	defer body.Close()

	csvReader := csv.NewReader(body)
	return csvReader.ReadAll()
}

func (service euvdService) convertAliasesToRelationships(aliasesCSV [][]string) ([]models.CVERelationship, error) {
	// check the format of the csv file; should break if the format changes so we explicitly investigate the change
	if len(aliasesCSV) == 0 || len(aliasesCSV[0]) != 2 || aliasesCSV[0][0] != csvEUVDColumnID || aliasesCSV[0][1] != csvCVEColumnID {
		return nil, fmt.Errorf("invalid/unexpected csv format; check the csv file provided by the EUVD")
	}

	relationships := make([]models.CVERelationship, 0, len(aliasesCSV))
	for i, row := range aliasesCSV[1:] { // exclude the header row
		if len(row) != 2 {
			return nil, fmt.Errorf("invalid csv format for row %d, expected length of 2 got: %d", i, len(row))
		}

		relationships = append(relationships, models.CVERelationship{
			SourceCVE:        row[0],
			TargetCVE:        row[1],
			RelationshipType: dtos.RelationshipTypeEUVD, // placeholder relationship type before resolving actual relations via the cve_relationships table
		})
	}

	return relationships, nil
}
