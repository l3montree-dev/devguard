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

package hashmigrations

import (
	"context"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/normalize"
	"gorm.io/gorm"
)

// legacyEdge is one row of the component_dependencies table this migration
// reads. The table is written by nothing any more; it exists only until every
// instance has been migrated onto the content-addressed storage.
type legacyEdge struct {
	AssetID          uuid.UUID `gorm:"column:asset_id"`
	AssetVersionName string    `gorm:"column:asset_version_name"`
	ComponentID      string    `gorm:"column:component_id"`
	DependencyID     string    `gorm:"column:dependency_id"`
}

// legacySBOM is one reconstructed SBOM: the artifact and source it belonged to,
// plus the tree rebuilt from the old edges.
type legacySBOM struct {
	ArtifactName string
	Source       string
	Tree         *normalize.MerkleTree
}

// The old table encoded structure in synthetic node ids:
//
//	ROOT -> artifact:<name> -> sbom:<source>@<name> -> <purls...>
const (
	legacyRootID          = "ROOT"
	legacyArtifactPrefix  = "artifact:"
	legacyInfoSourcePfx   = "sbom:"
	legacyDependencyLimit = 0 // unlimited
)

// reconstructSBOMs rebuilds one asset version's SBOMs from the legacy edges.
//
// Each (artifact, info source) pair becomes its own tree, hashed under the
// artifact's identity exactly as MerkleTreeFromCycloneDX does for a fresh scan.
// That is what makes a backfilled subtree collide with - and therefore
// deduplicate against - the same subtree ingested by a later scan.
func reconstructSBOMs(edges []legacyEdge) []legacySBOM {
	children := map[string][]string{}
	for _, edge := range edges {
		children[edge.ComponentID] = append(children[edge.ComponentID], edge.DependencyID)
	}

	var sboms []legacySBOM
	for _, artifactNode := range children[legacyRootID] {
		if !strings.HasPrefix(artifactNode, legacyArtifactPrefix) {
			continue
		}
		artifactName := strings.TrimPrefix(artifactNode, legacyArtifactPrefix)

		for _, sourceNode := range children[artifactNode] {
			if !strings.HasPrefix(sourceNode, legacyInfoSourcePfx) {
				continue
			}

			// "sbom:<source>@<artifact>" - the artifact suffix is redundant now
			source := strings.TrimPrefix(sourceNode, legacyInfoSourcePfx)
			if at := strings.LastIndex(source, "@"+artifactName); at >= 0 {
				source = source[:at]
			}

			sboms = append(sboms, legacySBOM{
				ArtifactName: artifactName,
				Source:       source,
				Tree: normalize.BuildMerkleTree(
					normalize.Adjacency{Children: componentEdgesBelow(children, sourceNode)},
					sourceNode,
					artifactName,
				),
			})
		}
	}
	return sboms
}

// componentEdgesBelow returns the edges reachable from sourceNode with every
// synthetic node dropped, so only real components reach the merkle tree. The
// source node itself is kept as the entry point; its children are the SBOM's
// direct dependencies.
func componentEdgesBelow(children map[string][]string, sourceNode string) map[string][]string {
	below := map[string][]string{}

	var walk func(node string)
	walk = func(node string) {
		if _, done := below[node]; done {
			return
		}
		kept := make([]string, 0, len(children[node]))
		for _, child := range children[node] {
			if isLegacySyntheticNode(child) {
				continue
			}
			kept = append(kept, child)
		}
		below[node] = kept
		for _, child := range kept {
			walk(child)
		}
	}
	walk(sourceNode)

	return below
}

func isLegacySyntheticNode(id string) bool {
	return id == legacyRootID ||
		strings.HasPrefix(id, legacyArtifactPrefix) ||
		strings.HasPrefix(id, legacyInfoSourcePfx)
}

// runMerkleBackfill rebuilds the content-addressed storage from the legacy
// component_dependencies table, so upgrading instances keep their SBOMs instead
// of having to rescan everything.
//
// It is idempotent: writing a tree that is already stored collides on the
// primary key and changes nothing.
func runMerkleBackfill(pool *pgxpool.Pool) error {
	db := database.NewGormDB(pool)
	ctx := context.Background()

	if !db.Migrator().HasTable("component_dependencies") {
		slog.Info("no legacy component_dependencies table, nothing to backfill")
		return nil
	}

	var assetVersions []struct {
		AssetID          uuid.UUID `gorm:"column:asset_id"`
		AssetVersionName string    `gorm:"column:asset_version_name"`
	}
	if err := db.Raw(`
		SELECT DISTINCT asset_id, asset_version_name FROM component_dependencies
	`).Scan(&assetVersions).Error; err != nil {
		return err
	}

	slog.Info("backfilling merkle sboms from component_dependencies", "assetVersions", len(assetVersions))

	sbomRepository := repositories.NewSBOMRepository(db)
	for i, key := range assetVersions {
		if err := db.Transaction(func(tx *gorm.DB) error {
			var edges []legacyEdge
			if err := tx.Raw(`
				SELECT asset_id, asset_version_name, component_id, dependency_id
				FROM component_dependencies
				WHERE asset_id = ? AND asset_version_name = ?
			`, key.AssetID, key.AssetVersionName).Scan(&edges).Error; err != nil {
				return err
			}

			for _, sbom := range reconstructSBOMs(edges) {
				if err := sbomRepository.SaveTree(ctx, tx, models.SBOM{
					AssetID:          key.AssetID,
					AssetVersionName: key.AssetVersionName,
					ArtifactName:     sbom.ArtifactName,
					Source:           sbom.Source,
				}, sbom.Tree); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}

		if (i+1)%50 == 0 {
			slog.Info("merkle backfill progress", "done", i+1, "total", len(assetVersions))
		}
	}

	slog.Info("merkle backfill complete", "assetVersions", len(assetVersions))
	return nil
}
