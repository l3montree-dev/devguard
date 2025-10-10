-- Copyright 2025 l3montree GmbH.
-- SPDX-License-Identifier: 	AGPL-3.0-or-later

CREATE TABLE IF NOT EXISTS public.artifact_upstream_url (
    artifact_name text NOT NULL,
    upstream_url text NOT NULL
);

ALTER TABLE public.artifact_upstream_url DROP CONSTRAINT IF EXISTS artifact_upstream_url_pkey;
ALTER TABLE public.artifact_upstream_url DROP CONSTRAINT IF EXISTS artifact_name_url_fkey;

ALTER TABLE ONLY public.artifact_upstream_url
    ADD CONSTRAINT artifact_upstream_url_pkey PRIMARY KEY (artifact_name, upstream_url);

ALTER TABLE ONLY public.artifact_upstream_url
    ADD CONSTRAINT artifact_name_url_fkey FOREIGN KEY (artifact_name) REFERENCES public.artifacts(artifact_name) ON DELETE CASCADE;