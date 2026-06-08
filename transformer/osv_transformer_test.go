package transformer

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/dtos"
)

func TestNonSemverLastAffectedFallsBackToVersions(t *testing.T) {
	osv := &dtos.OSV{
		ID: "TEST-0001",
		Affected: []dtos.Affected{
			{
				Package: dtos.Package{
					Ecosystem: "Maven",
					Purl:      "pkg:maven/org.example/lib",
				},
				Ranges: []dtos.Range{
					{
						Type: "ECOSYSTEM",
						Events: []dtos.SemverEvent{
							{Introduced: "4.5.0"},
							{LastAffected: "4.6.0.Final"}, // non-semver: cannot be parsed
						},
					},
				},
				Versions: []string{"4.5.0", "4.5.1", "4.6.0"},
			},
		},
	}

	components := AffectedComponentsFromOSV(osv)

	// range parsing must fail → falls back to the versions slice
	if len(components) != 3 {
		t.Fatalf("expected 3 version components from fallback, got %d", len(components))
	}
	for _, c := range components {
		if c.Version == nil {
			t.Errorf("expected exact version component, got range component")
		}
		if c.SemverIntroduced != nil || c.SemverFixed != nil {
			t.Errorf("expected no semver range on fallback component")
		}
	}
}

func TestLastAffectedGetsRespected(t *testing.T) {
	// read the test data
	b, err := os.ReadFile("testdata/ghsa-jmp9-x22r-554x.json")
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	// unmarshal the test data
	var osv dtos.OSV
	if err := json.Unmarshal(b, &osv); err != nil {
		t.Fatalf("failed to unmarshal test data: %v", err)
	}

	affectedComponents := AffectedComponentsFromOSV(&osv)
	if len(affectedComponents) != 3 {
		t.Fatalf("expected 3 affected component, got %d", len(affectedComponents))
	}

	// all purls should be the same - thats what we expect.
	expectedRanges := [][]string{
		{"6.2.0", "6.2.11"}, // this is a range with a fixed key
		{"6.0.0", "6.1.23"}, // this is a last affected range, where we just increment the patch version by one to make sure it fits into our semver_fixed model
		{"5.3.0", "5.3.45"}, // this again is a last affected range

	}
outer:
	for _, c := range affectedComponents {
		if c.PurlWithoutVersion != "pkg:maven/org.springframework/spring-core" {
			t.Errorf("unexpected purl, got %s", c.PurlWithoutVersion)
		}
		// expect the semver versions exist
		if c.SemverIntroduced == nil {
			t.Errorf("expected semver introduced to be set, got nil")
		}
		if c.SemverFixed == nil {
			t.Errorf("expected semver fixed to be set, got nil")
		}

		if c.SemverIntroduced != nil && c.SemverFixed != nil {
			for _, r := range expectedRanges {
				if *c.SemverIntroduced == r[0] && *c.SemverFixed == r[1] {
					// this is what we expect, so we can continue with the next component
					continue outer
				}
			}
			t.Errorf("unexpected semver range: %s - %s", *c.SemverIntroduced, *c.SemverFixed)
		}
	}
}
