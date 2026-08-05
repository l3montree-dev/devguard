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

package vexrules

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/stretchr/testify/require"
)

// The shapes below mirror a real dump taken from the devguard database this
// was benchmarked against (2026-08-04):
//
//	upstream_vex_rules:          269025 rows, 693 distinct CVE scopes
//	hottest CVE scope (rules):     7432 rules for a single CVE
//	dependency_vulns (state=open): 120775 rows, 1645 distinct CVEs
//	hottest CVE scope (vulns):       581 vulns for a single CVE
//
// generateSyntheticRules/Vulns reproduce that skew synthetically (a handful
// of very hot CVE buckets, the rest small) so the benchmark exercises the
// same worst case without embedding a real data dump in the repo.

func generateSyntheticRules(total, cveBuckets, hottestBucketSize int) []models.UpstreamVEXRule {
	rules := make([]models.UpstreamVEXRule, 0, total)
	remaining := total

	// a handful of hot buckets, decaying geometrically from hottestBucketSize
	hotBucketCount := 5
	bucketSize := hottestBucketSize
	for b := 0; b < hotBucketCount && remaining > 0; b++ {
		size := min(bucketSize, remaining)
		cve := fmt.Sprintf("CVE-2026-HOT-%d", b)
		for i := range size {
			rules = append(rules, models.UpstreamVEXRule{
				ID: uuid.NewString(),
				CELExpression: fmt.Sprintf(
					`vuln.cveId == %q && matchesPattern(vuln, ["*", "pkg:golang/example/pkg-%d@1.0.0", "*", "pkg:golang/stdlib@v1.25.0"])`,
					cve, i,
				),
			})
		}
		remaining -= size
		bucketSize = bucketSize / 2
	}

	// the rest spread thinly across the remaining CVE buckets
	remainingBuckets := max(cveBuckets-hotBucketCount, 1)
	perBucket := max(remaining/remainingBuckets, 1)
	for b := 0; b < remainingBuckets && remaining > 0; b++ {
		size := min(perBucket, remaining)
		cve := fmt.Sprintf("CVE-2026-COLD-%d", b)
		for i := range size {
			rules = append(rules, models.UpstreamVEXRule{
				ID: uuid.NewString(),
				CELExpression: fmt.Sprintf(
					`vuln.cveId == %q && matchesPattern(vuln, ["*", "pkg:golang/example/pkg-%d@1.0.0", "*", "pkg:golang/stdlib@v1.25.0"])`,
					cve, i,
				),
			})
		}
		remaining -= size
	}

	return rules
}

func generateSyntheticVulns(total, cveBuckets, hottestBucketSize int) []models.DependencyVuln {
	vulns := make([]models.DependencyVuln, 0, total)
	remaining := total

	hotBucketCount := 5
	bucketSize := hottestBucketSize
	makeVuln := func(cve string, i int) models.DependencyVuln {
		return models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				ID:               uuid.New(),
				AssetVersionName: "main",
			},
			CVEID:             cve,
			ComponentPurl:     fmt.Sprintf("pkg:golang/example/pkg-%d@1.0.0", i),
			VulnerabilityPath: []string{"ROOT", "pkg:golang/example/pkg-%d@1.0.0", "pkg:golang/stdlib@v1.25.0"},
		}
	}

	for b := 0; b < hotBucketCount && remaining > 0; b++ {
		size := min(bucketSize, remaining)
		cve := fmt.Sprintf("CVE-2026-HOT-%d", b)
		for i := range size {
			vulns = append(vulns, makeVuln(cve, i))
		}
		remaining -= size
		bucketSize = bucketSize / 2
	}

	remainingBuckets := max(cveBuckets-hotBucketCount, 1)
	perBucket := max(remaining/remainingBuckets, 1)
	for b := 0; b < remainingBuckets && remaining > 0; b++ {
		size := min(perBucket, remaining)
		cve := fmt.Sprintf("CVE-2026-COLD-%d", b)
		for i := range size {
			vulns = append(vulns, makeVuln(cve, i))
		}
		remaining -= size
	}

	return vulns
}

func BenchmarkCompileRulesFull(b *testing.B) {
	rules := generateSyntheticRules(269025, 693, 7432)

	for b.Loop() {
		if _, err := CompileRules(context.Background(), rules); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEvalCompiledRulesFull(b *testing.B) {
	rules := generateSyntheticRules(269025, 693, 7432)
	vulns := generateSyntheticVulns(120775, 1645, 581)

	compiled, err := CompileRules(context.Background(), rules)
	require.NoError(b, err)

	vulnMaps, err := PrepareVulnsForEval(context.Background(), vulns)
	require.NoError(b, err)

	for b.Loop() {
		if _, err := EvalCompiledRules(context.Background(), compiled, vulnMaps); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEvalCompiledRulesHotCVE isolates the worst single-CVE pairing seen
// in the real data (7432 rules x 581 vulns, all sharing one CVE) - even with
// CVE scoping, this single bucket alone is >4.3M CEL evaluations.
func BenchmarkEvalCompiledRulesHotCVE(b *testing.B) {
	rules := generateSyntheticRules(7432, 1, 7432)
	vulns := generateSyntheticVulns(581, 1, 581)

	compiled, err := CompileRules(context.Background(), rules)
	require.NoError(b, err)

	vulnMaps, err := PrepareVulnsForEval(context.Background(), vulns)
	require.NoError(b, err)

	for b.Loop() {
		if _, err := EvalCompiledRules(context.Background(), compiled, vulnMaps); err != nil {
			b.Fatal(err)
		}
	}
}
