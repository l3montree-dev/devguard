package vulndb

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
)

const (
	euvdIDMappingURL = "https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping" // URL to fetch the alias mapping from EUVD-IDs to CVE-IDs
	csvEUVDColumnID  = "euvd_id"                                                        // name of the csv columns, should be stable over all versions;if it changes it should break
	csvCVEColumnID   = "cve_id"
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
		httpClient:                &http.Client{},
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
	return relationships, service.writeCVERelationshipsToTable(ctx, tx, relationships)
}

func (service euvdService) fetchEUVDAliases() ([][]string, error) {
	req, err := http.NewRequest("GET", euvdIDMappingURL, nil)
	if err != nil {
		return nil, fmt.Errorf("could not build request to fetch csv file: %w", err)
	}

	resp, err := service.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not get csv file from EUVD api: %w", err)
	}
	defer resp.Body.Close()

	csvReader := csv.NewReader(resp.Body)
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
			RelationshipType: dtos.RelationshipTypeEUVD, // use explicit euvd relationships type to clearly identify them later on
		})
	}

	return relationships, nil
}

func (service euvdService) writeCVERelationshipsToTable(ctx context.Context, tx pgx.Tx, relationships []models.CVERelationship) error {
	if len(relationships) == 0 {
		return nil
	}

	targetCVEs := make([]string, len(relationships))
	sourceCVEs := make([]string, len(relationships))
	relationshipTypes := make([]string, len(relationships))
	for i, rel := range relationships {
		targetCVEs[i] = rel.TargetCVE
		sourceCVEs[i] = rel.SourceCVE
		relationshipTypes[i] = rel.RelationshipType
	}

	// insert directly into the live table; the cve_relationships primary key is kept
	// during bulk import so ON CONFLICT can deduplicate against rows already present.
	_, err := tx.Exec(ctx, `
		INSERT INTO cve_relationships (target_cve, source_cve, relationship_type)
		SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[])
		ON CONFLICT (target_cve, source_cve, relationship_type) DO NOTHING`,
		targetCVEs, sourceCVEs, relationshipTypes)
	if err != nil {
		return fmt.Errorf("could not insert euvd relationships into cve_relationships table: %w", err)
	}
	return nil
}
