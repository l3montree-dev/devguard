CREATE TABLE IF NOT EXISTS public.sbom_merkle_nodes (
    node_hash    UUID PRIMARY KEY,
    component_id TEXT NOT NULL
);

