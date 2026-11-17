// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package hashmigrations

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/gorm"
)

// the title of the component definition which was embedded before component definitions were uploaded per scope
const legacyComponentDefinition = "Grundschutz++ Compliance Mapping"

// the name of the seeded ISO 27001 Annex A catalog, which is not migrated
const legacyISO27001Framework = "ISO27001"

type legacyControl struct {
	Framework       string
	ControlID       string
	Title           string
	Class           string
	Description     string
	Importance      string
	SecurityLevel   string
	ParentControlID *string
}

type legacyControlHash struct {
	Framework   string `gorm:"column:framework"`
	ControlID   string `gorm:"column:control_id"`
	ControlHash string `gorm:"column:control_hash"`
	// a control with the same content in several frameworks is stored once
	Keep bool `gorm:"column:keep"`
}

type legacyPosture struct {
	ID               uuid.UUID
	ControlHash      string
	OrgID            uuid.UUID
	ProjectID        *uuid.UUID
	AssetID          *uuid.UUID
	AssetVersionName *string
}

type legacyPostureID struct {
	OldID       uuid.UUID `gorm:"column:old_id"`
	NewID       uuid.UUID `gorm:"column:new_id"`
	ControlHash string    `gorm:"column:control_hash"`
}

// runComplianceScopeMigration migrates the compliance data from global catalogs and components to scoped ones:
// controls are identified by their content hash, the frameworks and components which were used are activated
// in the org or project which used them and postures reference their control by hash.
// On installations without legacy data it only validates the foreign key of the postures.
func runComplianceScopeMigration(pool *pgxpool.Pool) error {
	start := time.Now()
	defer func() {
		slog.Info("compliance scope migration completed", "duration", time.Since(start))
	}()
	db := database.NewGormDB(pool)

	return db.Transaction(func(tx *gorm.DB) error {
		if err := deleteLegacyISO27001(tx); err != nil {
			return err
		}
		migrated, err := hashLegacyControls(tx)
		if err != nil {
			return err
		}
		if migrated > 0 {
			if err := createLegacyScopeFrameworks(tx); err != nil {
				return err
			}
			if err := rekeyLegacyPostures(tx); err != nil {
				return err
			}
			if err := scopeLegacyComponents(tx); err != nil {
				return err
			}
		}
		return cleanupLegacyControls(tx)
	})
}

func deleteLegacyISO27001(tx *gorm.DB) error {
	prefix := legacyISO27001Framework + ":%"
	result := tx.Exec(`DELETE FROM compliance_postures WHERE control_hash LIKE ?`, prefix)
	if result.Error != nil {
		return fmt.Errorf("could not delete the ISO 27001 postures: %w", result.Error)
	}
	postures := result.RowsAffected

	if err := tx.Exec(`DELETE FROM compliance_component_implements_controls WHERE framework_control_id LIKE ?`, prefix).Error; err != nil {
		return fmt.Errorf("could not delete the ISO 27001 controls of the components: %w", err)
	}
	if err := tx.Exec(`DELETE FROM mapped_controls WHERE framework_control_id LIKE ? OR related_framework = ?`, prefix, legacyISO27001Framework).Error; err != nil {
		return fmt.Errorf("could not delete the ISO 27001 mapped controls: %w", err)
	}

	result = tx.Exec(`DELETE FROM compliance_controls WHERE control_hash IS NULL AND framework = ?`, legacyISO27001Framework)
	if result.Error != nil {
		return fmt.Errorf("could not delete the ISO 27001 controls: %w", result.Error)
	}
	if postures > 0 || result.RowsAffected > 0 {
		slog.Info("deleted legacy ISO 27001 compliance data", "postures", postures, "controls", result.RowsAffected)
	}
	return nil
}

// hashLegacyControls calculates the hash of every control which was seeded before controls were identified by their content.
// The hashes are kept in a temporary table, so the following steps can map "<framework>:<control_id>" to the hash.
func hashLegacyControls(tx *gorm.DB) (int, error) {
	var controls []legacyControl
	if err := tx.Raw(`SELECT framework, control_id, title, class, description,
			COALESCE(importance, '') AS importance, COALESCE(security_level, '') AS security_level,
			parent_control_id
		FROM compliance_controls
		WHERE control_hash IS NULL
		ORDER BY framework, control_id`).Scan(&controls).Error; err != nil {
		return 0, fmt.Errorf("could not read legacy controls: %w", err)
	}

	if err := tx.Exec(`CREATE TEMP TABLE legacy_control_hashes (
			framework text NOT NULL,
			control_id text NOT NULL,
			control_hash text NOT NULL,
			keep boolean NOT NULL
		) ON COMMIT DROP`).Error; err != nil {
		return 0, fmt.Errorf("could not create legacy control hash table: %w", err)
	}
	if len(controls) == 0 {
		return 0, nil
	}

	hashes := make([]legacyControlHash, 0, len(controls))
	seen := make(map[string]bool, len(controls))
	for _, c := range controls {
		hash := models.FrameworkControl{
			ControlID:       c.ControlID,
			Title:           c.Title,
			Class:           c.Class,
			Description:     c.Description,
			Importance:      c.Importance,
			SecurityLevel:   c.SecurityLevel,
			ParentControlID: c.ParentControlID,
		}.CalculateHash()
		hashes = append(hashes, legacyControlHash{Framework: c.Framework, ControlID: c.ControlID, ControlHash: hash, Keep: !seen[hash]})
		seen[hash] = true
	}
	if err := tx.Table("legacy_control_hashes").CreateInBatches(hashes, 1000).Error; err != nil {
		return 0, fmt.Errorf("could not store legacy control hashes: %w", err)
	}

	// a control which was already uploaded with the same content keeps its row, the legacy row is deleted afterwards
	if err := tx.Exec(`UPDATE compliance_controls cc SET control_hash = h.control_hash
		FROM legacy_control_hashes h
		WHERE h.keep AND cc.control_hash IS NULL AND cc.framework = h.framework AND cc.control_id = h.control_id
			AND NOT EXISTS (SELECT 1 FROM compliance_controls existing WHERE existing.control_hash = h.control_hash)`).Error; err != nil {
		return 0, fmt.Errorf("could not set the hash of legacy controls: %w", err)
	}

	slog.Info("hashed legacy compliance controls", "count", len(controls), "distinct", len(seen))
	return len(controls), nil
}

// createLegacyScopeFrameworks activates every framework which has postures in the org or project of the postures.
// Postures of assets activate the framework in their project.
func createLegacyScopeFrameworks(tx *gorm.DB) error {
	if err := tx.Exec(`CREATE TEMP TABLE legacy_used_frameworks ON COMMIT DROP AS
		SELECT DISTINCT h.framework, cp.org_id, cp.project_id
		FROM compliance_postures cp
		JOIN legacy_control_hashes h ON cp.control_hash = h.framework || ':' || h.control_id`).Error; err != nil {
		return fmt.Errorf("could not collect the used frameworks: %w", err)
	}

	if err := tx.Exec(`INSERT INTO scope_frameworks (framework, org_id, project_id)
		SELECT framework, org_id, project_id FROM legacy_used_frameworks
		ON CONFLICT DO NOTHING`).Error; err != nil {
		return fmt.Errorf("could not create scope frameworks: %w", err)
	}

	if err := tx.Exec(`INSERT INTO scope_framework_controls (scope_framework_id, control_hash)
		SELECT DISTINCT sf.id, h.control_hash
		FROM legacy_used_frameworks used
		JOIN scope_frameworks sf ON sf.framework = used.framework
			AND sf.org_id = used.org_id
			AND sf.project_id IS NOT DISTINCT FROM used.project_id
			AND sf.asset_id IS NULL
		JOIN legacy_control_hashes h ON h.framework = sf.framework
		ON CONFLICT DO NOTHING`).Error; err != nil {
		return fmt.Errorf("could not link the controls to the scope frameworks: %w", err)
	}
	return nil
}

// rekeyLegacyPostures moves every posture to the hash of its control. The id of a posture is derived from the
// control, so each posture is copied to its new id and its events and statements are moved to the copy.
func rekeyLegacyPostures(tx *gorm.DB) error {
	var postures []legacyPosture
	if err := tx.Raw(`SELECT cp.id, h.control_hash, cp.org_id, cp.project_id, cp.asset_id, cp.asset_version_name
		FROM compliance_postures cp
		JOIN legacy_control_hashes h ON cp.control_hash = h.framework || ':' || h.control_id`).Scan(&postures).Error; err != nil {
		return fmt.Errorf("could not read legacy postures: %w", err)
	}
	if len(postures) == 0 {
		return nil
	}

	ids := make([]legacyPostureID, 0, len(postures))
	for _, p := range postures {
		ids = append(ids, legacyPostureID{
			OldID:       p.ID,
			NewID:       models.CalculateCompliancePostureHash(p.ControlHash, p.OrgID, p.ProjectID, p.AssetID, p.AssetVersionName),
			ControlHash: p.ControlHash,
		})
	}
	if err := tx.Exec(`CREATE TEMP TABLE legacy_posture_ids (
			old_id uuid NOT NULL,
			new_id uuid NOT NULL,
			control_hash text NOT NULL
		) ON COMMIT DROP`).Error; err != nil {
		return fmt.Errorf("could not create legacy posture id table: %w", err)
	}
	if err := tx.Table("legacy_posture_ids").CreateInBatches(ids, 1000).Error; err != nil {
		return fmt.Errorf("could not store legacy posture ids: %w", err)
	}

	var columns []string
	if err := tx.Raw(`SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'compliance_postures' AND column_name NOT IN ('id', 'control_hash')
		ORDER BY ordinal_position`).Scan(&columns).Error; err != nil {
		return fmt.Errorf("could not read the columns of the postures: %w", err)
	}
	insertColumns := make([]string, len(columns))
	selectColumns := make([]string, len(columns))
	for i, c := range columns {
		insertColumns[i] = `"` + c + `"`
		selectColumns[i] = `cp."` + c + `"`
	}

	// controls with the same content in several frameworks share a posture now, the most recently handled one is kept
	if err := tx.Exec(`INSERT INTO compliance_postures (id, control_hash, ` + strings.Join(insertColumns, ", ") + `)
		SELECT DISTINCT ON (m.new_id) m.new_id, m.control_hash, ` + strings.Join(selectColumns, ", ") + `
		FROM compliance_postures cp
		JOIN legacy_posture_ids m ON m.old_id = cp.id
		ORDER BY m.new_id, cp.last_state_change DESC NULLS LAST
		ON CONFLICT (id) DO NOTHING`).Error; err != nil {
		return fmt.Errorf("could not copy the postures: %w", err)
	}

	if err := tx.Exec(`UPDATE vuln_events e SET compliance_posture_id = m.new_id
		FROM legacy_posture_ids m
		WHERE e.compliance_posture_id = m.old_id`).Error; err != nil {
		return fmt.Errorf("could not move the events of the postures: %w", err)
	}

	// a posture can have one statement per component, a duplicate is deleted with its old posture
	if err := tx.Exec(`UPDATE compliance_component_implements_control_statements s SET compliance_posture_id = pick.new_id
		FROM (
			SELECT DISTINCT ON (m.new_id, s.compliance_component_id) s.id, m.new_id
			FROM compliance_component_implements_control_statements s
			JOIN legacy_posture_ids m ON m.old_id = s.compliance_posture_id
			ORDER BY m.new_id, s.compliance_component_id, s.id
		) pick
		WHERE s.id = pick.id
			AND NOT EXISTS (
				SELECT 1 FROM compliance_component_implements_control_statements existing
				WHERE existing.compliance_posture_id = pick.new_id AND existing.compliance_component_id = s.compliance_component_id
			)`).Error; err != nil {
		return fmt.Errorf("could not move the statements of the postures: %w", err)
	}

	if err := tx.Exec(`DELETE FROM compliance_postures
		WHERE id IN (SELECT old_id FROM legacy_posture_ids)
			AND id NOT IN (SELECT new_id FROM legacy_posture_ids)`).Error; err != nil {
		return fmt.Errorf("could not delete the legacy postures: %w", err)
	}

	slog.Info("moved compliance postures to the hash of their control", "count", len(postures))
	return nil
}

// scopeLegacyComponents copies every global component which is used by a statement to the org or project of the statement,
// moves the statements to the copy and deletes the global components.
func scopeLegacyComponents(tx *gorm.DB) error {
	if err := tx.Exec(`CREATE TEMP TABLE legacy_component_copies ON COMMIT DROP AS
		SELECT used.old_id, used.org_id, used.project_id, gen_random_uuid() AS new_id
		FROM (
			SELECT DISTINCT s.compliance_component_id AS old_id, cp.org_id, cp.project_id
			FROM compliance_component_implements_control_statements s
			JOIN compliance_postures cp ON cp.id = s.compliance_posture_id
			JOIN compliance_components c ON c.id = s.compliance_component_id
			WHERE c.org_id IS NULL
		) used`).Error; err != nil {
		return fmt.Errorf("could not collect the used components: %w", err)
	}

	if err := tx.Exec(`INSERT INTO compliance_components (id, uuid, title, description, component_definition, org_id, project_id, asset_id)
		SELECT m.new_id, c.uuid, c.title, c.description, ?, m.org_id, m.project_id, NULL
		FROM legacy_component_copies m
		JOIN compliance_components c ON c.id = m.old_id
		ON CONFLICT DO NOTHING`, legacyComponentDefinition).Error; err != nil {
		return fmt.Errorf("could not copy the components: %w", err)
	}

	// the definition might already have been uploaded in the scope, then its component is used
	if err := tx.Exec(`UPDATE legacy_component_copies m SET new_id = c.id
		FROM compliance_components legacy, compliance_components c
		WHERE legacy.id = m.old_id
			AND c.uuid = legacy.uuid
			AND c.component_definition = ?
			AND c.org_id = m.org_id
			AND c.project_id IS NOT DISTINCT FROM m.project_id
			AND c.asset_id IS NULL`, legacyComponentDefinition).Error; err != nil {
		return fmt.Errorf("could not map the components: %w", err)
	}

	if err := tx.Exec(`INSERT INTO compliance_component_implements_controls (framework_control_id, compliance_component_id, description)
		SELECT i.framework_control_id, m.new_id, i.description
		FROM legacy_component_copies m
		JOIN compliance_component_implements_controls i ON i.compliance_component_id = m.old_id
		ON CONFLICT DO NOTHING`).Error; err != nil {
		return fmt.Errorf("could not copy the implemented controls of the components: %w", err)
	}

	if err := tx.Exec(`UPDATE compliance_component_implements_control_statements s SET compliance_component_id = m.new_id
		FROM compliance_postures cp, legacy_component_copies m
		WHERE cp.id = s.compliance_posture_id
			AND m.old_id = s.compliance_component_id
			AND m.org_id = cp.org_id
			AND m.project_id IS NOT DISTINCT FROM cp.project_id`).Error; err != nil {
		return fmt.Errorf("could not move the statements to the scoped components: %w", err)
	}

	// their implemented controls are deleted by the database (cascade)
	if err := tx.Exec(`DELETE FROM compliance_components WHERE org_id IS NULL`).Error; err != nil {
		return fmt.Errorf("could not delete the global components: %w", err)
	}
	return nil
}

// cleanupLegacyControls deletes the controls which belong to no framework, e.g. duplicates or frameworks nobody used,
// and validates the foreign key of the postures, which could not be checked while they referenced "<framework>:<control_id>".
func cleanupLegacyControls(tx *gorm.DB) error {
	if err := tx.Exec(`DELETE FROM compliance_controls cc
		WHERE cc.control_hash IS NULL
			OR NOT EXISTS (SELECT 1 FROM scope_framework_controls sfc WHERE sfc.control_hash = cc.control_hash)`).Error; err != nil {
		return fmt.Errorf("could not delete unused controls: %w", err)
	}

	result := tx.Exec(`DELETE FROM compliance_postures cp
		WHERE NOT EXISTS (SELECT 1 FROM compliance_controls cc WHERE cc.control_hash = cp.control_hash)`)
	if result.Error != nil {
		return fmt.Errorf("could not delete postures without control: %w", result.Error)
	}
	if result.RowsAffected > 0 {
		slog.Warn("deleted compliance postures without control", "count", result.RowsAffected)
	}

	if err := tx.Exec(`ALTER TABLE compliance_postures VALIDATE CONSTRAINT fk_compliance_postures_control_hash`).Error; err != nil {
		return fmt.Errorf("could not validate the control foreign key of the postures: %w", err)
	}
	return nil
}
