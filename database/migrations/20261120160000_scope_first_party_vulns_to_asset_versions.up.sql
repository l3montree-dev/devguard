-- First-party vulnerability IDs must distinguish the same fingerprint in
-- different asset versions. Keep the Go HashToUUID algorithm (first 128 bits
-- of SHA-256) so future scans calculate the same IDs as this backfill.
CREATE TEMPORARY TABLE first_party_vulnerability_id_map ON COMMIT DROP AS
SELECT
    id AS old_id,
    substring(
        encode(
            sha256(
                convert_to(
                    (
                        CASE
                            WHEN COALESCE(fingerprint, '') <> '' THEN fingerprint
                            ELSE COALESCE(rule_id, '') || '/' ||
                                COALESCE(uri, '') || '/' ||
                                COALESCE(scanner_ids, '') || '/' ||
                                asset_id::text || '/' ||
                                asset_version_name
                        END
                    ) || '/' || asset_version_id::text,
                    'UTF8'
                )
            ),
            'hex'
        ),
        1,
        32
    )::uuid AS new_id
FROM public.first_party_vulnerabilities;

ALTER TABLE public.vuln_events
    DROP CONSTRAINT vuln_events_first_party_vuln_id_fkey;

UPDATE public.vuln_events AS event
SET first_party_vuln_id = id_map.new_id
FROM first_party_vulnerability_id_map AS id_map
WHERE event.first_party_vuln_id = id_map.old_id;

UPDATE public.first_party_vulnerabilities AS vuln
SET id = id_map.new_id
FROM first_party_vulnerability_id_map AS id_map
WHERE vuln.id = id_map.old_id;

ALTER TABLE public.vuln_events
    ADD CONSTRAINT vuln_events_first_party_vuln_id_fkey
    FOREIGN KEY (first_party_vuln_id)
    REFERENCES public.first_party_vulnerabilities(id)
    ON DELETE CASCADE;
