package transformer

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/package-url/packageurl-go"
)

// TestProcessRange exercises processRange against the OSV range/events spec:
// https://ossf.github.io/osv-schema/#requirements
func TestProcessRange(t *testing.T) {
	npmPurl, err := packageurl.FromString("pkg:npm/example-lib")
	if err != nil {
		t.Fatalf("failed to build npm purl: %v", err)
	}
	apkPurl, err := packageurl.FromString("pkg:apk/alpine/example-lib")
	if err != nil {
		t.Fatalf("failed to build apk purl: %v", err)
	}

	tests := []struct {
		name   string
		events []dtos.SemverEvent
		purl   packageurl.PackageURL
		want   []models.AffectedComponent
	}{
		{
			name: "simple introduced/fixed pair",
			events: []dtos.SemverEvent{
				{Introduced: "1.0.0"},
				{Fixed: "1.2.0"},
			},
			purl: npmPurl,
			want: []models.AffectedComponent{
				semverComponent(npmPurl, "1.0.0", "1.2.0"),
			},
		},
		{
			name: "introduced 0 means unbounded start - no lower bound recorded",
			events: []dtos.SemverEvent{
				{Introduced: "0"},
				{Fixed: "1.2.0"},
			},
			purl: npmPurl,
			want: []models.AffectedComponent{
				semverComponent(npmPurl, "", "1.2.0"),
			},
		},
		{
			name: "multiple fixed events after a single introduced (cherrypicks on other branches) will only record the first fixed event as the end of the range",
			events: []dtos.SemverEvent{
				{Introduced: "0"},
				{Fixed: "1.2.0"},
				{Fixed: "1.3.0"},
			},
			purl: npmPurl,
			want: []models.AffectedComponent{
				semverComponent(npmPurl, "", "1.2.0"),
			},
		},
		{
			name: "two independent introduced/fixed ranges",
			events: []dtos.SemverEvent{
				{Introduced: "1.0.0"},
				{Fixed: "1.2.0"},
				{Introduced: "2.0.0"},
				{Fixed: "2.5.0"},
			},
			purl: npmPurl,
			want: []models.AffectedComponent{
				semverComponent(npmPurl, "1.0.0", "1.2.0"),
				semverComponent(npmPurl, "2.0.0", "2.5.0"),
			},
		},
		{
			name: "last_affected with a semver-incrementable patch version",
			events: []dtos.SemverEvent{
				{Introduced: "1.0.0"},
				{LastAffected: "1.1.5"},
			},
			purl: npmPurl,
			want: []models.AffectedComponent{
				semverComponent(npmPurl, "1.0.0", "1.1.6"),
			},
		},
		{
			name: "last_affected that cannot be parsed as semver is skipped",
			events: []dtos.SemverEvent{
				{Introduced: "1.0.0"},
				{LastAffected: "not-a-version"},
			},
			purl: npmPurl,
			want: []models.AffectedComponent{},
		},
		{
			name: "no closing event at all yields a single open component",
			events: []dtos.SemverEvent{
				{Introduced: "1.0.0"},
			},
			purl: npmPurl,
			want: []models.AffectedComponent{
				semverComponent(npmPurl, "1.0.0", ""),
			},
		},
		{
			name: "unparseable fixed version on a semver ecosystem is skipped",
			events: []dtos.SemverEvent{
				{Introduced: "1.0.0"},
				{Fixed: "not-a-version"},
			},
			purl: npmPurl,
			want: []models.AffectedComponent{},
		},
		{
			name: "apk/deb/rpm ecosystems keep plain version strings instead of semver",
			events: []dtos.SemverEvent{
				{Introduced: "0"},
				{Fixed: "1.2.3-r0"},
			},
			purl: apkPurl,
			want: []models.AffectedComponent{
				versionComponent(apkPurl, "", "1.2.3-r0"),
			},
		},
		{
			name: "apk ecosystem also supports multiple fixed events for one introduced",
			events: []dtos.SemverEvent{
				{Introduced: "0"},
				{Fixed: "1.2.3-r0"},
				{Fixed: "1.2.4-r0"},
			},
			purl: apkPurl,
			want: []models.AffectedComponent{
				versionComponent(apkPurl, "", "1.2.3-r0"),
			},
		},
		{
			name:   "no events at all",
			events: []dtos.SemverEvent{},
			purl:   npmPurl,
			want:   []models.AffectedComponent{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := dtos.Range{Type: "ECOSYSTEM", Events: tt.events}
			got := processRange(r, "test-ecosystem", tt.purl)

			if len(got) != len(tt.want) {
				t.Fatalf("expected %d components, got %d: %+v", len(tt.want), len(got), got)
			}
			for i := range got {
				if !componentsEqual(got[i], tt.want[i]) {
					t.Errorf("component %d mismatch:\n got:  %+v\n want: %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func semverComponent(purl packageurl.PackageURL, introduced, fixed string) models.AffectedComponent {
	var semverIntroduced, semverFixed *string
	if introduced != "" {
		semverIntroduced = &introduced
	}
	if fixed != "" {
		semverFixed = &fixed
	}
	return newAffectedComponent("test-ecosystem", purl, semverIntroduced, semverFixed, nil, nil, nil)
}

func versionComponent(purl packageurl.PackageURL, introduced, fixed string) models.AffectedComponent {
	var versionIntroduced, versionFixed *string
	if introduced != "" {
		versionIntroduced = &introduced
	}
	if fixed != "" {
		versionFixed = &fixed
	}
	return newAffectedComponent("test-ecosystem", purl, nil, nil, nil, versionIntroduced, versionFixed)
}

func strPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func componentsEqual(a, b models.AffectedComponent) bool {
	return a.PurlWithoutVersion == b.PurlWithoutVersion &&
		a.Ecosystem == b.Ecosystem &&
		strPtrEqual(a.Version, b.Version) &&
		strPtrEqual(a.SemverIntroduced, b.SemverIntroduced) &&
		strPtrEqual(a.SemverFixed, b.SemverFixed) &&
		strPtrEqual(a.VersionIntroduced, b.VersionIntroduced) &&
		strPtrEqual(a.VersionFixed, b.VersionFixed)
}

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

func TestAlpineCVE2026_2006Transformation(t *testing.T) {
	b, err := os.ReadFile("testdata/alpine-cve-2026-2006.json")
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	var osv dtos.OSV
	if err := json.Unmarshal(b, &osv); err != nil {
		t.Fatalf("failed to unmarshal test data: %v", err)
	}

	components := AffectedComponentsFromOSV(&osv)

	// postgresql16 / Alpine:v3.22 has two "fixed" events after one "introduced"
	// event (16.12-r0, 16.13-r0) - every resulting component must carry a fixed version.
	var v322 []models.AffectedComponent
	for _, c := range components {
		if c.PurlWithoutVersion == "pkg:apk/alpine/postgresql16" && c.Ecosystem == "Alpine:v3.22" {
			v322 = append(v322, c)
		}
	}
	if len(v322) == 0 {
		t.Fatalf("expected components for postgresql16 / Alpine:v3.22")
	}
	for _, c := range v322 {
		if c.VersionFixed == nil {
			t.Errorf("postgresql16 / Alpine:v3.22 component has no fixed version set: %+v", c)
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

func TestIsUnmatchableRedHatEcosystem(t *testing.T) {
	unmatchable := []string{
		"Red Hat:hummingbird:1",            // Red Hat Hardened Images - no RHEL major at all
		"Red Hat:enterprise_linux:2.1::as", // pre-RHEL-3 legacy release
		"Red Hat:enterprise_linux:2.1::ws",
		"Red Hat:enterprise_linux:2.1::es",
		"Red Hat:enterprise_linux:2.1::aw",
		"Red Hat:rhel_application_stack:1", // standalone product version, no RHEL major
		"Red Hat:rhel_application_stack:2",
		"Red Hat:devtools:2020", // year-versioned product
		"Red Hat:devtools:2021",
		"Red Hat:hpc_solution:1.0",
		"Red Hat:rhel_application_server:2",
		"Red Hat:rhivos:1.0",
		"Red Hat:enterprise_ipa:1.0",
		"Red Hat:service_mesh:0",
	}
	for _, ecosystem := range unmatchable {
		if !isUnmatchableRedHatEcosystem(ecosystem) {
			t.Errorf("expected %q to be unmatchable", ecosystem)
		}
	}

	matchable := []string{
		"Red Hat:enterprise_linux:9::baseos",    // bare major, RHEL 9
		"Red Hat:enterprise_linux:8::appstream", // bare major, RHEL 8
		"Red Hat:enterprise_linux:10.2",         // bare major, RHEL 10 (unified minor versioning)
		"Red Hat:rhel_eus:9.4::baseos",          // EUS, minor-versioned
		"Red Hat:rhel_aus:8.4::appstream",       // AUS, minor-versioned
		"Red Hat:jboss_core_services:1::el8",    // add-on product, "elN" suffix
		"Red Hat:openstack:18.0::el9",           // add-on product, "elN" suffix
		"Red Hat:enterprise_mrg:2:server:el6",   // "elN" suffix in a different field position
		"Red Hat:enterprise_linux:11::baseos",  // bare major, RHEL 11 (future major)
		"Red Hat:rhel_eus:11.4::baseos",        // EUS, RHEL 11
		"Red Hat:jboss_core_services:1::el11",  // add-on product, "elN" suffix, RHEL 11
	}
	for _, ecosystem := range matchable {
		if isUnmatchableRedHatEcosystem(ecosystem) {
			t.Errorf("expected %q to be matchable", ecosystem)
		}
	}

	// non-Red-Hat ecosystems are never touched by this filter
	other := []string{"Debian:13", "Alpine:v3.22", "npm"}
	for _, ecosystem := range other {
		if isUnmatchableRedHatEcosystem(ecosystem) {
			t.Errorf("expected %q (non-Red-Hat ecosystem) to be left alone", ecosystem)
		}
	}
}
