package vulndb

import (
	"testing"
)

func TestDebianCveToAffectedComponentVersionComparison(t *testing.T) {
	pkg := "libfoo"
	cveID := "CVE-2025-0001"

	cases := []struct {
		name           string
		repoVersion    string
		fixedVersion   string
		expectAffected bool
	}{
		{"current_smaller_than_fixed", "1.2.3-1", "1.2.4-1", true},
		{"current_equal_fixed", "1.2.4-1", "1.2.4-1", false},
		{"current_greater_than_fixed", "1.2.5-1", "1.2.4-1", false},
		{"empty_fixed_version", "1.2.3-1", "", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			d := debianCVE{
				Description: "test",
				Releases: map[string]debianCveRelease{
					"bookworm": {
						Status:       "open",
						Repositories: map[string]string{"bookworm": tc.repoVersion},
						FixedVersion: tc.fixedVersion,
						Urgency:      "not yet assigned",
					},
				},
			}

			got := debianCveToAffectedComponent(pkg, cveID, d)

			if tc.expectAffected {
				if len(got) == 0 {
					t.Fatalf("expected affected components for case %s, got none", tc.name)
				}
				// ensure returned components reference the CVE
				found := false
				for _, a := range got {
					if a.Name == pkg {
						for _, c := range a.CVE {
							if c.CVE == cveID {
								found = true
								break
							}
						}
					}
				}
				if !found {
					t.Fatalf("expected affected component containing CVE %s in case %s, got: %+v", cveID, tc.name, got)
				}
			} else {
				if len(got) != 0 {
					t.Fatalf("expected no affected components for case %s, got: %+v", tc.name, got)
				}
			}
		})
	}
}
