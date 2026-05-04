-- Create trusted_entities table
CREATE TABLE IF NOT EXISTS public.trusted_entities (
    trusted_entity_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID,
    project_id UUID,
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