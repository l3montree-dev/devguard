// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package repositories

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type sbomRepository struct {
	utils.Repository[string, models.SBOM, *gorm.DB]
	db *gorm.DB
}

func NewSBOMRepository(db *gorm.DB) *sbomRepository {
	return &sbomRepository{
		Repository: newGormRepository[string, models.SBOM](db),
		db:         db,
	}
}

// Save persists one SBOM: its subtrees, then the pivot row pointing at the root.
//
// Edges are inserted with ON CONFLICT DO NOTHING, so subtrees the instance has
// already stored - whether from this artifact, another artifact, or another
// organization entirely - cost nothing. That is where the deduplication comes
// from.
//
// The pivot row is keyed by (asset, artifact, origin), so re-ingesting the same
// origin moves it to the new root hash rather than accumulating one row per
// content revision. The previous root's subtrees are left in place for the
// garbage collector, because other SBOMs may still reference them.
func (r *sbomRepository) Save(ctx context.Context, tx *gorm.DB, sbom models.SBOM, tree *normalize.MerkleTree) error {
	db := r.GetDB(ctx, tx)

	edges := tree.Edges()
	rows := make([]models.SBOMMerkleEdge, 0, len(edges))
	for _, e := range edges {
		rows = append(rows, models.SBOMMerkleEdge{
			SubtreeHash:                 e.SubtreeHash,
			ComponentID:                 e.ComponentID,
			DirectDependencySubtreeHash: e.DirectDependencySubtreeHash,
		})
	}

	if len(rows) > 0 {
		if err := db.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(rows, 1000).Error; err != nil {
			return errors.Wrap(err, "could not store sbom subtrees")
		}
	}

	// drop any previous revision of this origin before pointing at the new root
	if err := db.Where(
		"asset_id = ? AND asset_version_name = ? AND artifact_name = ? AND origin = ?",
		sbom.AssetID, sbom.AssetVersionName, sbom.ArtifactName, sbom.Origin,
	).Delete(&models.SBOM{}).Error; err != nil {
		return errors.Wrap(err, "could not clear previous sbom revision")
	}

	sbom.RootSubtreeHash = tree.Root
	sbom.UpdatedAt = time.Now()
	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&sbom).Error; err != nil {
		return errors.Wrap(err, "could not store sbom")
	}
	return nil
}

// FindByAssetVersion returns every SBOM of an asset version - one row per
// artifact and origin. This is the entry point for scanning: fetch the SBOMs,
// then load whichever trees you need.
func (r *sbomRepository) FindByAssetVersion(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionName string) ([]models.SBOM, error) {
	var sboms []models.SBOM
	err := r.GetDB(ctx, tx).
		Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName).
		Order("artifact_name ASC, origin ASC").
		Find(&sboms).Error
	return sboms, err
}

// FindByArtifact returns every SBOM of a single artifact.
func (r *sbomRepository) FindByArtifact(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionName, artifactName string) ([]models.SBOM, error) {
	var sboms []models.SBOM
	err := r.GetDB(ctx, tx).
		Where("asset_id = ? AND asset_version_name = ? AND artifact_name = ?", assetID, assetVersionName, artifactName).
		Order("origin ASC").
		Find(&sboms).Error
	return sboms, err
}

// LoadTree materializes one SBOM by walking down from its root hash.
//
// The walk terminates because the stored graph is acyclic: edges that would
// close a cycle are dropped at build time. UNION rather than UNION ALL also
// means a subtree shared by many parents is visited once, which is what bounds
// the fan-out on wide graphs.
func (r *sbomRepository) LoadTree(ctx context.Context, tx *gorm.DB, rootSubtreeHash string) (*normalize.MerkleTree, error) {
	var rows []models.SBOMMerkleEdge

	err := r.GetDB(ctx, tx).Raw(`
		WITH RECURSIVE walk AS (
			SELECT subtree_hash, component_id, direct_dependency_subtree_hash
			FROM sbom_merkle_edges
			WHERE subtree_hash = ?
		UNION
			SELECT e.subtree_hash, e.component_id, e.direct_dependency_subtree_hash
			FROM sbom_merkle_edges e
			JOIN walk w ON e.subtree_hash = w.direct_dependency_subtree_hash
		)
		SELECT subtree_hash, component_id, direct_dependency_subtree_hash FROM walk
	`, rootSubtreeHash).Scan(&rows).Error
	if err != nil {
		return nil, errors.Wrap(err, "could not walk sbom subtrees")
	}

	edges := make([]normalize.MerkleEdge, 0, len(rows))
	for _, row := range rows {
		edges = append(edges, normalize.MerkleEdge{
			SubtreeHash:                 row.SubtreeHash,
			ComponentID:                 row.ComponentID,
			DirectDependencySubtreeHash: row.DirectDependencySubtreeHash,
		})
	}

	return normalize.MerkleTreeFromEdges(edges, rootSubtreeHash)
}

// FindSBOMsContainingComponent walks upward from every subtree carrying the
// given component and reports the SBOMs that reach it - the "which artifacts
// are affected by this vulnerable purl" query.
//
// Reaching the sboms table is the stop condition; there is no ROOT sentinel to
// match. Subtrees that no SBOM references simply never join and drop out, so
// stale subtrees cannot produce phantom results.
func (r *sbomRepository) FindSBOMsContainingComponent(ctx context.Context, tx *gorm.DB, componentID string) ([]models.SBOM, error) {
	var sboms []models.SBOM

	err := r.GetDB(ctx, tx).Raw(`
		WITH RECURSIVE up AS (
			SELECT subtree_hash
			FROM sbom_merkle_edges
			WHERE component_id = ?
		UNION
			SELECT e.subtree_hash
			FROM sbom_merkle_edges e
			JOIN up u ON e.direct_dependency_subtree_hash = u.subtree_hash
		)
		SELECT s.* FROM sboms s
		JOIN up ON s.root_subtree_hash = up.subtree_hash
	`, componentID).Scan(&sboms).Error
	if err != nil {
		return nil, errors.Wrap(err, "could not walk up to affected sboms")
	}
	return sboms, nil
}

// DeleteByArtifact removes an artifact's SBOMs. Only the pivot rows go: the
// subtrees stay for the garbage collector, since other artifacts are likely to
// share them.
func (r *sbomRepository) DeleteByArtifact(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionName, artifactName string) error {
	return r.GetDB(ctx, tx).Where(
		"asset_id = ? AND asset_version_name = ? AND artifact_name = ?",
		assetID, assetVersionName, artifactName,
	).Delete(&models.SBOM{}).Error
}

// DeleteByOrigin removes a single SBOM source from an artifact.
func (r *sbomRepository) DeleteByOrigin(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionName, artifactName, origin string) error {
	return r.GetDB(ctx, tx).Where(
		"asset_id = ? AND asset_version_name = ? AND artifact_name = ? AND origin = ?",
		assetID, assetVersionName, artifactName, origin,
	).Delete(&models.SBOM{}).Error
}

// CollectGarbage deletes subtrees no SBOM can reach any more.
//
// Content addressing means an edge is never updated in place and never deleted
// on rescan, so unreferenced subtrees accumulate: every superseded revision of
// every SBOM leaves its old spine behind. Only reachability from the sboms
// table can tell those apart from subtrees still shared by someone else, which
// is why this is a mark and sweep rather than reference counting.
//
// It returns the number of deleted edges.
func (r *sbomRepository) CollectGarbage(ctx context.Context, tx *gorm.DB) (int64, error) {
	result := r.GetDB(ctx, tx).Exec(`
		WITH RECURSIVE reachable AS (
			SELECT root_subtree_hash AS subtree_hash FROM sboms
		UNION
			SELECT e.direct_dependency_subtree_hash
			FROM sbom_merkle_edges e
			JOIN reachable r ON e.subtree_hash = r.subtree_hash
			WHERE e.direct_dependency_subtree_hash IS NOT NULL
		)
		DELETE FROM sbom_merkle_edges e
		WHERE NOT EXISTS (
			SELECT 1 FROM reachable r WHERE r.subtree_hash = e.subtree_hash
		)
	`)
	if result.Error != nil {
		return 0, errors.Wrap(result.Error, "could not collect sbom garbage")
	}
	return result.RowsAffected, nil
}
