package normalize

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMergeCdxBomsSimple(t *testing.T) {
	b1 := &cdx.BOM{
		Components: &[]cdx.Component{{
			Name:       "comp-a",
			PackageURL: "pkg:maven/org.example/comp-a@1.0.0",
		}},
	}
	b2 := &cdx.BOM{
		Components: &[]cdx.Component{{
			Name:       "comp-b",
			PackageURL: "pkg:maven/org.example/comp-b@2.0.0",
		}},
		Vulnerabilities: &[]cdx.Vulnerability{{
			ID: "CVE-XYZ",
		}},
	}

	merged := MergeCdxBoms(nil, b1, b2)
	if merged == nil || merged.Components == nil {
		t.Fatalf("expected merged BOM with components, got nil")
	}
	if len(*merged.Components) != 2 {
		t.Fatalf("expected 2 components in merged BOM, got %d", len(*merged.Components))
	}

	assert.Len(t, *merged.Vulnerabilities, 1)
}
