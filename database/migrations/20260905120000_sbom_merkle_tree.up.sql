-- Copyright (C) 2026 l3montree GmbH
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as
-- published by the Free Software Foundation, either version 3 of the
-- License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

-- Content-addressed (Merkle) SBOM storage.
--
-- Replaces the mutable (component_id, dependency_id) edge table
-- component_dependencies, whose last-write-wins semantics meant two artifacts
-- sharing a component could not disagree about that component's transitive
-- dependencies. Here a component's subtree_hash covers its entire child set, so
-- disagreeing artifacts produce different hashes and both edge sets coexist,
-- while agreeing artifacts collide on the primary key and are stored once -
-- across the whole instance.

-- Hashes are UUID: the leading 128 bits of the sha256, matching how
-- utils.HashToUUID already derives identity elsewhere. Fixed-width and half the
-- size of the raw digest, where hex TEXT would be four times the size.
CREATE TABLE IF NOT EXISTS public.sbom_merkle_edges (
    subtree_hash                   UUID NOT NULL,
    component_id                   TEXT NOT NULL,
    -- NULL marks a leaf. The row still exists so the leaf's component id stays
    -- resolvable from its subtree hash: a leaf has no outgoing edge to carry it.
    direct_dependency_subtree_hash UUID,
    -- component_id is deliberately NOT part of the key: the hash already covers
    -- it, so two component ids under one subtree hash would be a sha256
    -- collision. Including it only widened the index by a purl per row.
    -- NULLS NOT DISTINCT so a leaf row can only be inserted once (PG15+).
    CONSTRAINT sbom_merkle_edges_unique
        UNIQUE NULLS NOT DISTINCT (subtree_hash, direct_dependency_subtree_hash)
);


-- upward traversal (vulnerable purl -> affected SBOMs)
CREATE INDEX IF NOT EXISTS idx_sbom_merkle_edges_child
    ON public.sbom_merkle_edges (direct_dependency_subtree_hash);

-- seed of the upward traversal
CREATE INDEX IF NOT EXISTS idx_sbom_merkle_edges_component
    ON public.sbom_merkle_edges (component_id);

-- One row per asset version + artifact + SBOM source, pointing at the root of
-- that SBOM's tree. Replaces the synthetic `artifact:` / `sbom:` nodes that used
-- to be stored as component_dependencies rows, and doubles as the stop
-- condition for the upward walk, which is why no ROOT sentinel is needed.
--
-- root_subtree_hash carries no foreign key: sbom_merkle_edges.subtree_hash is
-- non-unique by design (a component with n children has n rows), so it cannot
-- be a foreign key target.
-- Primary key leads with (asset_id, asset_version_name): that is the lookup
-- driving normal reads (all SBOMs for an asset version), and a composite PK's
-- index already serves any query on a leading prefix of its columns, so this
-- ordering makes a separate (asset_id, asset_version_name) index redundant.
CREATE TABLE IF NOT EXISTS public.sboms (
    asset_id           UUID NOT NULL,
    asset_version_name TEXT NOT NULL,
    artifact_name      TEXT NOT NULL,
    source             TEXT NOT NULL,
    root_subtree_hash  UUID NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_id, asset_version_name, artifact_name, source, root_subtree_hash),
    CONSTRAINT fk_sboms_asset_version
        FOREIGN KEY (asset_version_name, asset_id)
        REFERENCES public.asset_versions (name, asset_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sboms_root
    ON public.sboms (root_subtree_hash);
