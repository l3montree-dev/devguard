CREATE TABLE IF NOT EXISTS public.sbom_merkle_nodes (
    node_hash uuid PRIMARY KEY,
    component_id text
)