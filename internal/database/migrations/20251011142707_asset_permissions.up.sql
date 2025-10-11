-- Copyright (C) 2025 l3montree GmbH
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

-- Migration to add asset-level permissions for all existing assets
-- This migration sets up the three-tier permission system: Organization -> Project -> Asset

-- Step 1: Create asset permissions for all existing assets
-- For each asset, create permissions for member and admin roles

-- Asset Member can READ assets
INSERT INTO casbin_rule (ptype, v0, v1, v2, v3)
SELECT DISTINCT 
    'p',
    'asset::' || a.id::text || '|role::member',
    'domain::' || o.id::text,
    'asset::' || a.id::text || '|obj::asset',
    'act::read'
FROM assets a
JOIN projects p ON a.project_id = p.id
JOIN organizations o ON p.organization_id = o.id
WHERE NOT EXISTS (
    SELECT 1 FROM casbin_rule cr
    WHERE cr.ptype = 'p'
    AND cr.v0 = 'asset::' || a.id::text || '|role::member'
    AND cr.v1 = 'domain::' || o.id::text
    AND cr.v2 = 'asset::' || a.id::text || '|obj::asset'
    AND cr.v3 = 'act::read'
);

-- Asset Admin can READ, UPDATE, DELETE assets
INSERT INTO casbin_rule (ptype, v0, v1, v2, v3)
SELECT DISTINCT 
    'p',
    'asset::' || a.id::text || '|role::admin',
    'domain::' || o.id::text,
    'asset::' || a.id::text || '|obj::asset',
    action
FROM assets a
JOIN projects p ON a.project_id = p.id
JOIN organizations o ON p.organization_id = o.id
CROSS JOIN (VALUES ('act::read'), ('act::update'), ('act::delete')) AS actions(action)
WHERE NOT EXISTS (
    SELECT 1 FROM casbin_rule cr
    WHERE cr.ptype = 'p'
    AND cr.v0 = 'asset::' || a.id::text || '|role::admin'
    AND cr.v1 = 'domain::' || o.id::text
    AND cr.v2 = 'asset::' || a.id::text || '|obj::asset'
    AND cr.v3 = action
);

-- Step 2: Make asset admin inherit from asset member
-- This gives asset admins all permissions that members have
INSERT INTO casbin_rule (ptype, v0, v1, v2)
SELECT DISTINCT
    'g',
    'asset::' || a.id::text || '|role::admin',
    'asset::' || a.id::text || '|role::member',
    'domain::' || o.id::text
FROM assets a
JOIN projects p ON a.project_id = p.id
JOIN organizations o ON p.organization_id = o.id
WHERE NOT EXISTS (
    SELECT 1 FROM casbin_rule cr
    WHERE cr.ptype = 'g'
    AND cr.v0 = 'asset::' || a.id::text || '|role::admin'
    AND cr.v1 = 'asset::' || a.id::text || '|role::member'
    AND cr.v2 = 'domain::' || o.id::text
);

-- Step 3: Link project admin role to asset admin role
-- This makes project admins automatically asset admins
INSERT INTO casbin_rule (ptype, v0, v1, v2)
SELECT DISTINCT
    'g',
    'project::' || p.id::text || '|role::admin',
    'asset::' || a.id::text || '|role::admin',
    'domain::' || o.id::text
FROM assets a
JOIN projects p ON a.project_id = p.id
JOIN organizations o ON p.organization_id = o.id
WHERE NOT EXISTS (
    SELECT 1 FROM casbin_rule cr
    WHERE cr.ptype = 'g'
    AND cr.v0 = 'project::' || p.id::text || '|role::admin'
    AND cr.v1 = 'asset::' || a.id::text || '|role::admin'
    AND cr.v2 = 'domain::' || o.id::text
);

-- Step 4: Grant asset member role to all current project members
-- This gives existing project members direct asset member roles
-- Note: This does NOT create automatic inheritance - future project members won't automatically get asset access
INSERT INTO casbin_rule (ptype, v0, v1, v2)
SELECT DISTINCT
    'g',
    user_role.v0,  -- user::<user-id>
    'asset::' || a.id::text || '|role::member',
    'domain::' || o.id::text
FROM assets a
JOIN projects p ON a.project_id = p.id
JOIN organizations o ON p.organization_id = o.id
JOIN casbin_rule user_role ON 
    user_role.ptype = 'g'
    AND user_role.v1 = 'project::' || p.id::text || '|role::member'
    AND user_role.v2 = 'domain::' || o.id::text
    AND user_role.v0 LIKE 'user::%'
WHERE NOT EXISTS (
    SELECT 1 FROM casbin_rule cr
    WHERE cr.ptype = 'g'
    AND cr.v0 = user_role.v0
    AND cr.v1 = 'asset::' || a.id::text || '|role::member'
    AND cr.v2 = 'domain::' || o.id::text
);

