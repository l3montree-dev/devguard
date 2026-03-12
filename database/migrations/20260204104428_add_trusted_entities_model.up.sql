-- Create trusted_entities table
CREATE TABLE IF NOT EXISTS public.trusted_entities (
    trusted_entity_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID,
    project_id UUID,
    entity_type TEXT NOT NULL CHECK (entity_type IN ('organization', 'project')),
    trustscore FLOAT8 NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

ALTER TABLE ONLY public.trusted_entities
    ADD CONSTRAINT fk_organization FOREIGN KEY (organization_id) REFERENCES public.organizations(id)
        ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE ONLY public.trusted_entities
    ADD CONSTRAINT fk_project FOREIGN KEY (project_id) REFERENCES public.projects(id)
        ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE ONLY public.trusted_entities
    ADD CONSTRAINT trusted_entities_unique_entity UNIQUE (organization_id, project_id);
ALTER TABLE ONLY public.trusted_entities
    ADD CONSTRAINT valid_entity CHECK (
        (organization_id IS NOT NULL AND project_id IS NULL AND entity_type = 'organization')
        OR
        (organization_id IS NULL AND project_id IS NOT NULL AND entity_type = 'project')
    )