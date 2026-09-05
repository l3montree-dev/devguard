-- Content-addressed (Merkle) SBOM storage.
--
-- Replaces the mutable (component_id, dependency_id) edge table
-- `component_dependencies`, whose last-write-wins semantics meant two artifacts
-- sharing a component could not disagree about that component's transitive
-- dependencies. Here a component's subtree_hash covers its entire child set, so
-- disagreeing artifacts produce different hashes and both edge sets coexist,
-- while agreeing artifacts collide on the primary key and are stored once.

CREATE TABLE IF NOT EXISTS sbom_merkle_edges (
    subtree_hash                   TEXT NOT NULL,
    component_id                   TEXT NOT NULL,
    -- NULL marks a leaf. The row still exists so the leaf's purl stays
    -- resolvable from its subtree hash.
    direct_dependency_subtree_hash TEXT,
    -- NULLS NOT DISTINCT so a leaf row can only be inserted once (PG15+).
    CONSTRAINT sbom_merkle_edges_pkey
        UNIQUE NULLS NOT DISTINCT (subtree_hash, component_id, direct_dependency_subtree_hash)
);

-- downward traversal (SBOM root -> components) and child-set lookup
CREATE INDEX IF NOT EXISTS idx_sbom_merkle_edges_subtree
    ON sbom_merkle_edges (subtree_hash);

-- upward traversal (vulnerable purl -> affected SBOMs)
CREATE INDEX IF NOT EXISTS idx_sbom_merkle_edges_child
    ON sbom_merkle_edges (direct_dependency_subtree_hash);

-- seed of the upward traversal
CREATE INDEX IF NOT EXISTS idx_sbom_merkle_edges_component
    ON sbom_merkle_edges (component_id);

-- One row per asset version + artifact + SBOM origin. Replaces the synthetic
-- `artifact:` / `sbom:` nodes that used to be stored as component_dependencies
-- rows. root_subtree_hash carries no FK: sbom_merkle_edges.subtree_hash is
-- non-unique by design (a node with n children has n rows), so it cannot be a
-- foreign key target.
CREATE TABLE IF NOT EXISTS sboms (
    root_subtree_hash  TEXT NOT NULL,
    artifact_name      TEXT NOT NULL,
    asset_version_name TEXT NOT NULL,
    asset_id           UUID NOT NULL,
    origin             TEXT NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (root_subtree_hash, artifact_name, asset_version_name, asset_id, origin),
    CONSTRAINT fk_sboms_asset_version
        FOREIGN KEY (asset_version_name, asset_id)
        REFERENCES asset_versions (name, asset_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sboms_asset_version
    ON sboms (asset_id, asset_version_name);

CREATE INDEX IF NOT EXISTS idx_sboms_root
    ON sboms (root_subtree_hash);
