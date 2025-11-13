-- Copyright 2025 l3montree GmbH.
-- SPDX-License-Identifier: 	AGPL-3.0-or-later

ALTER TABLE public.assets
ADD COLUMN IF NOT EXISTS metadata jsonb;