package commands

import (
	"os"
	"slices"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
)

// TestGitleaksSupplementarySBOMMergeNestsUnderGitleaks reproduces a real-world
// scan: a trivy image scan of the devguard-scanner image (whose root
// component is a purl-less container, i.e. "unidentifiable") merged with the
// gitleaks supplementary SBOM baked into that same image. golang.org/x/crypto
// must end up nested under the gitleaks module (transitively, via gitleaks's
// own real dependencies like sprig/afero - not necessarily as a direct
// child), not attached directly to root - see MakeValid/
// InvalidSBOMGraphFromCycloneDX for why the root's lack of a PackageURL
// previously caused the enriched subtree to be pruned as unreachable.
//
// It also checks that a dependency gitleaks shares with other binaries in
// the image (spf13/viper, at the exact version gitleaks itself requires) is
// attached only under gitleaks, not additionally flattened onto root - a
// symptom of the go-modules vendoring bug fixed in nix/gitleaks.nix
// (proxyVendor) that this SBOM fixture was regenerated to exercise.
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

	refByPurl := map[string]string{}
	for _, c := range *bom.Components {
		if c.PackageURL != "" {
			refByPurl[c.PackageURL] = c.BOMRef
		}
	}
	gitleaksRef, ok := refByPurl["pkg:golang/github.com/zricethezav/gitleaks/v8@8.30.1"]
	if !ok {
		t.Fatal("gitleaks module component not found in merged SBOM")
	}
	cryptoRef, ok := refByPurl["pkg:golang/golang.org/x/crypto@v0.35.0"]
	if !ok {
		t.Fatal("crypto component not found in merged SBOM")
	}
	viperRef, ok := refByPurl["pkg:golang/github.com/spf13/viper@v1.19.0"]
	if !ok {
		t.Fatal("viper@v1.19.0 component not found in merged SBOM")
	}

	childrenOf := map[string][]string{}
	parentsOf := map[string][]string{}
	for _, d := range *bom.Dependencies {
		if d.Dependencies == nil {
			continue
		}
		childrenOf[d.Ref] = *d.Dependencies
		for _, c := range *d.Dependencies {
			parentsOf[c] = append(parentsOf[c], d.Ref)
		}
	}

	reachable := func(from, to string) bool {
		seen := map[string]bool{}
		var visit func(string) bool
		visit = func(ref string) bool {
			if ref == to {
				return true
			}
			if seen[ref] {
				return false
			}
			seen[ref] = true
			return slices.ContainsFunc(childrenOf[ref], visit)
		}
		return visit(from)
	}

	for _, c := range childrenOf[rootRef] {
		if c == cryptoRef {
			t.Error("crypto is attached directly to root instead of being nested under gitleaks")
		}
		if c == viperRef {
			t.Error("viper@v1.19.0 is attached directly to root instead of being nested under gitleaks")
		}
	}

	if !reachable(gitleaksRef, cryptoRef) {
		t.Error("crypto is not reachable from gitleaks")
	}

	if got := parentsOf[viperRef]; len(got) != 1 || got[0] != gitleaksRef {
		t.Errorf("viper@v1.19.0 should have exactly one parent (gitleaks), got %v", got)
	}
}
