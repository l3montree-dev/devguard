package scanner

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "component": {
      "type": "application",
      "bom-ref": "nix/store/xyz-gitleaks/bin/gitleaks",
      "name": "nix/store/xyz-gitleaks/bin/gitleaks"
    }
  }
}`

func tarLayerWithFiles(t *testing.T, files map[string]string) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	layer, err := tarball.LayerFromReader(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	return layer
}

func TestDiscoverSupplementarySBOMsInImage(t *testing.T) {
	t.Run("finds a supplementary SBOM under the configured path", func(t *testing.T) {
		layer := tarLayerWithFiles(t, map[string]string{
			"sboms/gitleaks.json": testSBOM,
			"usr/bin/other":       "not json",
		})
		img, err := mutate.AppendLayers(empty.Image, layer)
		require.NoError(t, err)

		boms, err := DiscoverSupplementarySBOMsInImage(img, "/sboms")
		require.NoError(t, err)
		require.Len(t, boms, 1)
		assert.Equal(t, "nix/store/xyz-gitleaks/bin/gitleaks", boms[0].Metadata.Component.Name)
	})

	t.Run("resolves a symlink under the configured path to its target (Nix dockerTools layout)", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: "nix/store/xyz-gitleaks-sbom/sboms/gitleaks.json",
			Mode: 0644,
			Size: int64(len(testSBOM)),
		}))
		_, err := tw.Write([]byte(testSBOM))
		require.NoError(t, err)
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     "sboms/gitleaks.json",
			Typeflag: tar.TypeSymlink,
			Linkname: "/nix/store/xyz-gitleaks-sbom/sboms/gitleaks.json",
		}))
		require.NoError(t, tw.Close())

		layer, err := tarball.LayerFromReader(bytes.NewReader(buf.Bytes()))
		require.NoError(t, err)
		img, err := mutate.AppendLayers(empty.Image, layer)
		require.NoError(t, err)

		boms, err := DiscoverSupplementarySBOMsInImage(img, "/sboms")
		require.NoError(t, err)
		require.Len(t, boms, 1)
		assert.Equal(t, "nix/store/xyz-gitleaks/bin/gitleaks", boms[0].Metadata.Component.Name)
	})

	t.Run("ignores json files outside the configured path", func(t *testing.T) {
		layer := tarLayerWithFiles(t, map[string]string{
			"other/gitleaks.json": testSBOM,
		})
		img, err := mutate.AppendLayers(empty.Image, layer)
		require.NoError(t, err)

		boms, err := DiscoverSupplementarySBOMsInImage(img, "/sboms")
		require.NoError(t, err)
		assert.Empty(t, boms)
	})
}

func TestDiscoverSupplementarySBOMsInDir(t *testing.T) {
	t.Run("finds supplementary SBOMs in the directory", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "gitleaks.json"), []byte(testSBOM), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "not-json.txt"), []byte("hello"), 0644))

		boms, err := DiscoverSupplementarySBOMsInDir(dir)
		require.NoError(t, err)
		require.Len(t, boms, 1)
		assert.Equal(t, "nix/store/xyz-gitleaks/bin/gitleaks", boms[0].Metadata.Component.Name)
	})

	t.Run("missing directory yields no SBOMs and no error", func(t *testing.T) {
		boms, err := DiscoverSupplementarySBOMsInDir(filepath.Join(t.TempDir(), "does-not-exist"))
		require.NoError(t, err)
		assert.Empty(t, boms)
	})
}
