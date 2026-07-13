package commands

import (
	"os"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
)

// TestGitleaksSupplementarySBOMMergeNestsUnderGitleaks reproduces a real-world
// scan: a trivy image scan of the devguard-scanner image (whose root
// component is a purl-less container, i.e. "unidentifiable") merged with the
// gitleaks supplementary SBOM baked into that same image. golang.org/x/crypto
// must end up nested under the gitleaks module, not attached directly to
// root - see MakeValid/InvalidSBOMGraphFromCycloneDX for why the root's lack
// of a PackageURL previously caused the enriched subtree to be pruned as
// unreachable.
func TestGitleaksSupplementarySBOMMergeNestsUnderGitleaks(t *testing.T) {
	mainBytes, err := os.ReadFile("testdata/gitleaks_repro/main.json")
	if err != nil {
		t.Fatal(err)
	}
	extraBytes, err := os.ReadFile("testdata/gitleaks_repro/gitleaks.json")
	if err != nil {
		t.Fatal(err)
	}

	bom, err := scanner.BomFromBytes(mainBytes)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := scanner.BomFromBytes(extraBytes)
	if err != nil {
		t.Fatal(err)
	}

	if err := mergeSupplementarySBOMs(bom, []*cyclonedx.BOM{extra}); err != nil {
		t.Fatal(err)
	}

	rootRef := bom.Metadata.Component.BOMRef

	gitleaksRef := ""
	cryptoRef := ""
	for _, c := range *bom.Components {
		if c.PackageURL == "pkg:golang/github.com/zricethezav/gitleaks/v8@8.30.1" {
			gitleaksRef = c.BOMRef
		}
		if c.PackageURL == "pkg:golang/golang.org/x/crypto@v0.35.0" {
			cryptoRef = c.BOMRef
		}
	}
	if gitleaksRef == "" {
		t.Fatal("gitleaks module component not found in merged SBOM")
	}
	if cryptoRef == "" {
		t.Fatal("crypto component not found in merged SBOM")
	}

	childrenOf := map[string][]string{}
	for _, d := range *bom.Dependencies {
		if d.Dependencies != nil {
			childrenOf[d.Ref] = *d.Dependencies
		}
	}

	for _, c := range childrenOf[rootRef] {
		if c == cryptoRef {
			t.Error("crypto is attached directly to root instead of being nested under gitleaks")
		}
	}
	found := false
	for _, c := range childrenOf[gitleaksRef] {
		if c == cryptoRef {
			found = true
		}
	}
	if !found {
		t.Error("crypto is not nested under gitleaks")
	}
}
