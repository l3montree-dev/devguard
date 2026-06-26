-- migration to delete currently orphaned rbac rules left over after the org/project/asset got deleted

-- 1. Orphaned orgs (prefix domain::<id>|)
DELETE FROM public.casbin_rule cr
WHERE (cr.ptype = 'g' AND cr.v2 LIKE 'domain::%' -- ptype g contains the domain always in v2
       AND NOT EXISTS (SELECT FROM public.organizations o WHERE cr.v2 = 'domain::' || o.id::text))
   OR (cr.ptype = 'p' AND cr.v1 LIKE 'domain::%' -- ptype p contains the domain always in v1
       AND NOT EXISTS (SELECT FROM public.organizations o WHERE cr.v1 = 'domain::' || o.id::text));

-- 2. Orphaned projects (prefix project::<id>|)
DELETE FROM public.casbin_rule cr
WHERE EXISTS (
  SELECT FROM (VALUES (cr.v0),(cr.v1),(cr.v2),(cr.v3)) AS vals(v)
  WHERE vals.v LIKE 'project::%' --filter for only project rules
    AND substring(vals.v from 'project::([0-9a-fA-F-]+)') -- ignore any values with role suffixes
    NOT IN (SELECT id::text FROM public.projects)
); -- then check if any of the ids have no reference in the projects table

-- 3. Orphaned assets (prefix asset::<id>|)
DELETE FROM public.casbin_rule cr
WHERE EXISTS ( 
  SELECT FROM (VALUES (cr.v0),(cr.v1),(cr.v2),(cr.v3)) AS vals(v)
  WHERE vals.v LIKE 'asset::%' --filter for only asset rules
    AND substring(vals.v from 'asset::([0-9a-fA-F-]+)') -- ignore any values with role suffixes
    NOT IN (SELECT id::text FROM public.assets)
); -- then check if any of the ids have no reference in the assets table