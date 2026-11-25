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
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/celrules"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/dtos"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

// legacyDependencyProxyConfig is the json config-file payload used before the proxy switched to yaml cel rules.
type legacyDependencyProxyConfig struct {
	Rules         *string           `json:"rules"`
	MinReleaseAge *int              `json:"minReleaseAge"`
	Registries    map[string]string `json:"registries"`
}

type migratedDependencyProxyConfig struct {
	Registries map[string]any         `yaml:"registries,omitempty"`
	Rules      []celrules.PackageRule `yaml:"rules,omitempty"`
}

// legacyGlobToRegex converts a legacy wildcard pattern into an anchored regex. The legacy matcher
// treated '*' as "any characters" and everything else literally.
func legacyGlobToRegex(pattern string) string {
	parts := strings.Split(pattern, "*")
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	return "^" + strings.Join(parts, ".*") + "$"
}

// convertLegacyDependencyProxyConfig converts a legacy json config into the yaml cel rule format.
// It returns false if content is not a legacy config.
func convertLegacyDependencyProxyConfig(content string) (string, bool, error) {
	var legacy legacyDependencyProxyConfig
	if err := json.Unmarshal([]byte(content), &legacy); err != nil {
		return "", false, nil
	}
	// yaml is a superset of json - a json object without the legacy fields might be a new config
	if legacy.Rules == nil && legacy.MinReleaseAge == nil {
		return "", false, nil
	}

	var migrated migratedDependencyProxyConfig
	if len(legacy.Registries) > 0 {
		migrated.Registries = make(map[string]any, len(legacy.Registries))
		for eco, url := range legacy.Registries {
			switch eco {
			case "deb":
				migrated.Registries[eco] = map[string]string{"url": url}
			case "npm":
				migrated.Registries[eco] = []map[string]string{{"url": url}}
			default:
				migrated.Registries[eco] = url
			}
		}
	}

	// rule order is kept: the legacy matcher and cel rules both let the last matching rule win
	if legacy.Rules != nil {
		for line := range strings.SplitSeq(*legacy.Rules, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			action := celrules.ActionDeny
			if strings.HasPrefix(line, "!") {
				action = celrules.ActionAllow
			}
			migrated.Rules = append(migrated.Rules, celrules.PackageRule{
				Name:   line,
				Action: action,
				Expr:   "pkg.purl.matches(" + strconv.Quote(legacyGlobToRegex(strings.TrimPrefix(line, "!"))) + ")",
			})
		}
	}

	// appended last, so allow rules cannot bypass it - the legacy min release age was checked independently of the rules
	if legacy.MinReleaseAge != nil && *legacy.MinReleaseAge > 0 {
		migrated.Rules = append(migrated.Rules, celrules.PackageRule{
			Name:   fmt.Sprintf("min release age %dh", *legacy.MinReleaseAge),
			Action: celrules.ActionDeny,
			Expr:   fmt.Sprintf(`has(pkg.releasedAt) && now() - timestamp(pkg.releasedAt) < duration("%dh")`, *legacy.MinReleaseAge),
		})
	}

	out, err := yaml.Marshal(migrated)
	if err != nil {
		return "", true, err
	}
	if err := dtos.ValidateDependencyProxyConfigFile(out); err != nil {
		return "", true, fmt.Errorf("migrated config is invalid: %w", err)
	}
	if _, err := celrules.ParsePackageRules(string(out)); err != nil {
		return "", true, fmt.Errorf("migrated rules are invalid: %w", err)
	}
	return string(out), true, nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// convertScalarNpmRegistry rewrites `npm: <url>` into the list format introduced with scoped npm registries.
// It works on the yaml node tree, so rules and comments of the config are kept.
// It returns false if content has no scalar npm registry.
func convertScalarNpmRegistry(content string) (string, bool, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil || len(doc.Content) == 0 {
		return "", false, nil
	}
	npm := mappingValue(mappingValue(doc.Content[0], "registries"), "npm")
	if npm == nil || npm.Kind != yaml.ScalarNode {
		return "", false, nil
	}

	url := npm.Value
	*npm = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "url"},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: url},
		},
	}}}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return "", true, err
	}
	return string(out), true, nil
}

func runDependencyProxyConfigMigration(pool *pgxpool.Pool) error {
	return rewriteDependencyProxyConfigs(pool, "dependency proxy config migration", convertLegacyDependencyProxyConfig)
}

func runNpmRegistryListMigration(pool *pgxpool.Pool) error {
	return rewriteDependencyProxyConfigs(pool, "npm registry list migration", convertScalarNpmRegistry)
}

// rewriteDependencyProxyConfigs replaces every org, project and asset dependency proxy config for which
// convert reports a change.
func rewriteDependencyProxyConfigs(pool *pgxpool.Pool, name string, convert func(content string) (string, bool, error)) error {
	start := time.Now()
	defer func() {
		slog.Info(name+" completed", "duration", time.Since(start))
	}()
	db := database.NewGormDB(pool)

	return db.Transaction(func(tx *gorm.DB) error {
		for _, table := range []string{"organizations", "projects", "assets"} {
			var rows []struct {
				ID      string
				Content string
			}
			if err := tx.Raw(`SELECT id, config_files->>'` + dtos.DependencyProxyConfigFileID + `' AS content FROM ` + table + ` WHERE config_files->>'` + dtos.DependencyProxyConfigFileID + `' IS NOT NULL`).Scan(&rows).Error; err != nil {
				return fmt.Errorf("failed to read dependency proxy configs from %s: %w", table, err)
			}

			for _, row := range rows {
				migrated, isLegacy, err := convert(row.Content)
				if err != nil {
					// keep the original config - the proxy reports the parse error for this scope
					slog.Warn("could not migrate dependency proxy config, keeping it", "table", table, "id", row.ID, "error", err)
					continue
				}
				if !isLegacy {
					continue
				}
				if err := tx.Exec(`UPDATE `+table+` SET config_files = jsonb_set(config_files, ?, to_jsonb(?::text)) WHERE id = ?`, "{"+dtos.DependencyProxyConfigFileID+"}", migrated, row.ID).Error; err != nil {
					return fmt.Errorf("failed to update dependency proxy config of %s %s: %w", table, row.ID, err)
				}
			}
			slog.Info("migrated dependency proxy configs", "table", table, "count", len(rows))
		}
		return nil
	})
}
