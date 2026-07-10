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

package scanner

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/pkg/errors"
)

// decodeSBOM reads a single supplementary CycloneDX SBOM from r.
func decodeSBOM(r io.Reader, source string) (*cyclonedx.BOM, error) {
	var bom cyclonedx.BOM
	if err := cyclonedx.NewBOMDecoder(r, cyclonedx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, errors.Wrapf(err, "could not decode supplementary SBOM %q", source)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		slog.Warn("supplementary SBOM has no root component, skipping", "path", source)
		return nil, nil
	}
	return &bom, nil
}

// DiscoverSupplementarySBOMsInDir walks dir looking for *.json files and
// decodes each one as a CycloneDX SBOM. dir that does not exist is not an
// error - it simply yields no SBOMs.
func DiscoverSupplementarySBOMsInDir(dir string) ([]*cyclonedx.BOM, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, nil
	}

	var boms []*cyclonedx.BOM
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		bom, err := decodeSBOM(f, path)
		if err != nil {
			return err
		}
		if bom != nil {
			boms = append(boms, bom)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return boms, nil
}

// DiscoverSupplementarySBOMsInImage flattens img's filesystem and looks for
// *.json files under sbomPath (an absolute path inside the image, e.g.
// "/sboms"), decoding each one as a CycloneDX SBOM.
//
// Image builders commonly merge such paths in as symlinks into a content-
// addressed store rather than as regular files (e.g. Nix's dockerTools,
// which symlinks /sboms/foo.json -> /nix/store/<hash>-foo/sboms/foo.json),
// so this makes two passes over the flattened filesystem: the first
// resolves any symlinks found under sbomPath to their target path, the
// second reads the regular files at the direct and resolved paths.
func DiscoverSupplementarySBOMsInImage(img v1.Image, sbomPath string) ([]*cyclonedx.BOM, error) {
	prefix := strings.TrimPrefix(filepath.Clean(sbomPath), "/")

	targets, err := jsonTargetsUnderPrefix(img, prefix)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}

	rc := mutate.Extract(img)
	defer rc.Close()

	remaining := make(map[string]bool, len(targets))
	for _, t := range targets {
		remaining[t] = true
	}

	var boms []*cyclonedx.BOM
	tr := tar.NewReader(rc)
	for len(remaining) > 0 {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "could not read image filesystem")
		}

		name := strings.TrimPrefix(filepath.Clean(hdr.Name), "/")
		if hdr.Typeflag != tar.TypeReg || !remaining[name] {
			continue
		}
		delete(remaining, name)

		bom, err := decodeSBOM(tr, hdr.Name)
		if err != nil {
			return nil, err
		}
		if bom != nil {
			boms = append(boms, bom)
		}
	}
	return boms, nil
}

// jsonTargetsUnderPrefix walks img's flattened filesystem once and returns the
// paths of every *.json entry under prefix: regular files as-is, and symlinks
// resolved to their (single-hop) target path.
func jsonTargetsUnderPrefix(img v1.Image, prefix string) ([]string, error) {
	rc := mutate.Extract(img)
	defer rc.Close()

	var targets []string
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "could not read image filesystem")
		}

		name := strings.TrimPrefix(filepath.Clean(hdr.Name), "/")
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		if !strings.HasPrefix(name, prefix+"/") && name != prefix {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeReg:
			targets = append(targets, name)
		case tar.TypeSymlink, tar.TypeLink:
			target := hdr.Linkname
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(name), target)
			}
			targets = append(targets, strings.TrimPrefix(filepath.Clean(target), "/"))
		}
	}
	return targets, nil
}

// LoadImageFromTarball opens a local OCI image tarball (as produced by
// `docker save` / `trivy image --input`) for filesystem inspection. The
// tarball may optionally be gzip-compressed (e.g. images built by Nix's
// dockerTools are typically shipped as a .tar.gz) - since gzip streams
// aren't seekable and tarball.Image's opener gets invoked repeatedly (once
// per layer plus manifest/config lookups), decompressing on every call would
// re-read and re-inflate the entire archive each time. Instead, gzipped
// input is decompressed once into a temp file up front, and that temp file
// (cheap to reopen) is used for the actual image loading. The returned
// cleanup func removes the temp file, if one was created, and must be
// called once the caller is done with the image.
func LoadImageFromTarball(path string) (img v1.Image, cleanup func(), err error) {
	cleanup = func() {}

	f, err := os.Open(path)
	if err != nil {
		return nil, cleanup, err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	magic, err := br.Peek(2)
	if err != nil || magic[0] != 0x1f || magic[1] != 0x8b {
		// not gzip (or too short to tell) - use the file as-is
		img, err = tarball.ImageFromPath(path, nil)
		return img, cleanup, err
	}

	tmp, err := os.CreateTemp("", "devguard-image-*.tar")
	if err != nil {
		return nil, cleanup, errors.Wrap(err, "could not create temp file for decompressed image")
	}
	cleanup = func() { os.Remove(tmp.Name()) }

	gz, err := gzip.NewReader(br)
	if err != nil {
		return nil, cleanup, errors.Wrap(err, "could not decompress gzip tarball")
	}
	if _, err := io.Copy(tmp, gz); err != nil {
		tmp.Close()
		return nil, cleanup, errors.Wrap(err, "could not decompress gzip tarball")
	}
	if err := tmp.Close(); err != nil {
		return nil, cleanup, err
	}

	img, err = tarball.ImageFromPath(tmp.Name(), nil)
	return img, cleanup, err
}

// LoadRemoteImage pulls an image reference from a registry for filesystem
// inspection, using the default keychain (assumes MaybeLoginIntoOciRegistry
// has already been called if credentials are needed).
func LoadRemoteImage(ctx context.Context, image string) (v1.Image, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse image reference")
	}
	return remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
}
