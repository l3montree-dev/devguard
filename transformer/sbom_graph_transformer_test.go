package transformer

import (
	"fmt"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/stretchr/testify/assert"
)

func lib(purl string) cdx.Component {
	return cdx.Component{BOMRef: purl, Name: purl, PackageURL: purl, Type: cdx.ComponentTypeLibrary}
}

func TestSBOMGraphToMerkleTree(t *testing.T) {
	artifactName := "pkg:golang/test-artifact"
	origin := "test-origin"

	t.Run("root has no purl: chain is ROOT -> artifact -> infosource -> leaf", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata:    &cdx.Metadata{Component: &cdx.Component{BOMRef: artifactName, Name: artifactName}},
			Components:  &[]cdx.Component{lib("pkg:npm/leaf@1.0.0"), lib("pkg:npm/intermediate@1.0.0")},
			Dependencies: &[]cdx.Dependency{
				{Ref: artifactName, Dependencies: &[]string{"pkg:npm/intermediate@1.0.0"}},
				{Ref: "pkg:npm/intermediate@1.0.0", Dependencies: &[]string{"pkg:npm/leaf@1.0.0"}},
			},
		}

		g, err := normalize.SBOMGraphFromCycloneDX(bom, artifactName, origin)
		assert.NoError(t, err)
		edges := SBOMGraphToMerkleTree(g)

		fmt.Println("Edges:", edges)
	})
}
