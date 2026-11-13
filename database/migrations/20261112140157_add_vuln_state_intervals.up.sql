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

-- detectedInArtifact / fixedInArtifact events record when a vuln was added to or removed from an artifact
ALTER TABLE public.vuln_events ADD COLUMN artifact_id uuid;

-- the past link history cannot be recovered, so every existing link is assumed to exist since the vuln was opened first
INSERT INTO public.vuln_events (id, created_at, type, user_id, dependency_vuln_id, artifact_id, created_by_vex_rule)
WITH direct_open AS (
    SELECT dependency_vuln_id, min(created_at) AS opened_at
    FROM public.vuln_events
    WHERE dependency_vuln_id IS NOT NULL AND type IN ('detected', 'reopened')
    GROUP BY dependency_vuln_id
), group_open AS (
    SELECT asset_signature, min(created_at) AS opened_at
    FROM public.vuln_events
    WHERE dependency_vuln_id IS NULL AND asset_signature IS NOT NULL AND type IN ('detected', 'reopened')
    GROUP BY asset_signature
)
SELECT gen_random_uuid(),
       coalesce(least(d.opened_at, g.opened_at), dv.created_at),
       'detectedInArtifact', 'system', adv.dependency_vuln_id, adv.artifact_id, false
FROM public.artifact_dependency_vulns adv
JOIN public.dependency_vulns dv ON dv.id = adv.dependency_vuln_id
LEFT JOIN direct_open d ON d.dependency_vuln_id = dv.id
LEFT JOIN group_open g ON g.asset_signature = dv.asset_signature;

-- the foreign key and index are created after the backfill, checking them per inserted row is much slower
ALTER TABLE public.vuln_events ADD CONSTRAINT vuln_events_artifact_id_fkey
    FOREIGN KEY (artifact_id) REFERENCES public.artifacts(id) ON DELETE CASCADE;

CREATE INDEX idx_vuln_events_artifact_id ON public.vuln_events (artifact_id, dependency_vuln_id, created_at)
    WHERE artifact_id IS NOT NULL;

-- one row per period a dependency vuln stayed in one state, derived from its vuln events.
-- fixed is the default state and has no rows: a vuln without an interval at a point in time was fixed then.
CREATE TABLE public.vuln_state_intervals (
    dependency_vuln_id uuid NOT NULL REFERENCES public.dependency_vulns(id) ON DELETE CASCADE,
    asset_version_id   uuid NOT NULL,
    state              text NOT NULL,
    valid_from         timestamptz NOT NULL,
    valid_to           timestamptz,
    -- hashtextextended(cve_id || '|' || component_purl, 0) to count unique cve + purl pairs
    cve_purl_hash           bigint NOT NULL,
    risk               double precision NOT NULL,
    cvss               real NOT NULL,
    fixable            boolean NOT NULL,
    PRIMARY KEY (dependency_vuln_id, valid_from)
);

INSERT INTO public.vuln_state_intervals
WITH events AS (
    SELECT e.dependency_vuln_id, e.created_at, e.id, e.type
    FROM public.vuln_events e
    WHERE e.dependency_vuln_id IS NOT NULL
      AND e.type IN ('detected', 'reopened', 'fixed', 'falsePositive', 'accepted', 'markedForTransfer')
    UNION ALL
    -- group events apply to every vuln with the same asset signature
    SELECT dv.id, e.created_at, e.id, e.type
    FROM public.vuln_events e
    JOIN public.dependency_vulns dv ON dv.asset_signature = e.asset_signature
    WHERE e.dependency_vuln_id IS NULL
      AND e.type IN ('detected', 'reopened', 'fixed', 'falsePositive', 'accepted', 'markedForTransfer')
), grouped AS (
    -- every detected event belongs to the decision of the last non-detected event before it
    SELECT *, count(*) FILTER (WHERE type <> 'detected')
                  OVER (PARTITION BY dependency_vuln_id ORDER BY created_at, id) AS decision_group
    FROM events
), states AS (
    SELECT dependency_vuln_id, created_at, id,
           CASE
               WHEN type = 'reopened' THEN 'open'
               WHEN type <> 'detected' THEN type
               -- a scan does not reopen a vuln a user accepted or marked as false positive
               WHEN decision IN ('falsePositive', 'accepted') THEN decision
               ELSE 'open'
           END AS state
    FROM (
        SELECT *, first_value(type) OVER (PARTITION BY dependency_vuln_id, decision_group ORDER BY created_at, id) AS decision
        FROM grouped
    ) decided
), changes AS (
    SELECT *, lag(state) OVER (PARTITION BY dependency_vuln_id ORDER BY created_at, id) AS prev_state
    FROM states
), boundaries AS (
    SELECT dependency_vuln_id, created_at, state,
           lead(created_at) OVER (PARTITION BY dependency_vuln_id ORDER BY created_at, id) AS next_change
    FROM changes
    WHERE prev_state IS NULL OR state <> prev_state
)
SELECT b.dependency_vuln_id, dv.asset_version_id, b.state, b.created_at, b.next_change,
       hashtextextended(dv.cve_id || '|' || dv.component_purl, 0),
       coalesce(dv.risk_assessment, 0), coalesce(c.cvss, 0),
       coalesce(dv.direct_dependency_fixed_version, '') <> ''
FROM boundaries b
JOIN public.dependency_vulns dv ON dv.id = b.dependency_vuln_id
LEFT JOIN public.cves c ON c.cve = dv.cve_id
WHERE b.state <> 'fixed';

CREATE INDEX idx_vuln_state_intervals_asset_version ON public.vuln_state_intervals (asset_version_id, state, valid_from, valid_to);

-- without statistics on artifact_id the planner does not use the new index for the link events of an artifact
ANALYZE public.vuln_events (artifact_id);
ANALYZE public.vuln_state_intervals;
