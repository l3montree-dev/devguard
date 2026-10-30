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

package shared

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/l3montree-dev/devguard/dtos"

	"github.com/l3montree-dev/devguard/utils"
	"github.com/ulikunitz/xz"
	"pault.ag/go/debian/control"
)

const (
	DebRegistry         = "http://deb.debian.org"
	MetasnapLayout      = "20060102T150405Z"
	DebSnapshotRegistry = "http://snapshot.debian.org/archive"
	MaxPackagesXZSize   = 100 << 20
	maxInReleaseSize    = 10 << 20
)

var (
	DebComponents    = []string{"main"}
	DebArchitectures = []string{"amd64", "arm64"}
	DebSuites        = map[string][]string{
		"debian":          {"trixie", "trixie-updates", "bookworm", "bookworm-updates"},
		"debian-security": {"trixie-security", "bookworm-security"},
	}
)

func IsDebSuiteSupported(archive, suite string) bool {
	return slices.Contains(DebSuites[archive], suite)
}

type DebRelease struct {
	control.Paragraph
	SHA256 []control.SHA256FileHash `delim:"\n" strip:"\n\r\t "`
}

type DebPackage struct {
	Paragraph  control.Paragraph
	ReleasedAt time.Time
}

type MetasnapEntry struct {
	Version   string
	Suite     string
	FirstSeen time.Time
}

type DebPackageIndex struct {
	DebRelease  DebRelease
	DebPackages []DebPackage
}

func (r DebRelease) File(path string) (control.FileHash, bool) {
	for _, entry := range r.SHA256 {
		if entry.Filename == path {
			return entry.FileHash, true
		}
	}
	return control.FileHash{}, false
}

//go:embed debian-keyring/*.asc
var debianKeyringFiles embed.FS

var debianKeyring = sync.OnceValues(func() (string, error) {
	files, err := fs.Glob(debianKeyringFiles, "debian-keyring/*.asc")
	if err != nil {
		return "", err
	}

	var str strings.Builder
	for _, name := range files {
		data, err := debianKeyringFiles.ReadFile(name)
		if err != nil {
			return "", err
		}
		str.Write(data)
		str.WriteString("\n")
	}
	return str.String(), nil
})

func DefaultDebConfig() dtos.DebianRegistryConfig {
	keyring, err := debianKeyring()
	if err != nil {
		panic(fmt.Errorf("failed to load debian keyring: %w", err))
	}

	return dtos.DebianRegistryConfig{
		URLRegistryConfig: dtos.URLRegistryConfig{
			URL: DebRegistry,
		},
		Keyring: &keyring,
	}
}

func SnapshotDebConfig() dtos.DebianRegistryConfig {
	return dtos.DebianRegistryConfig{
		URLRegistryConfig: dtos.URLRegistryConfig{
			URL: DebSnapshotRegistry,
		},
		Keyring: DefaultDebConfig().Keyring,
	}
}

var ErrDebFileNotListed = errors.New("file not listed in InRelease")

func parseArmoredKeyring(armored *string) (*openpgp.EntityList, error) {
	if armored == nil || *armored == "" {
		return nil, nil
	}

	r := strings.NewReader(*armored)
	var keyring openpgp.EntityList
	for {
		block, err := armor.Decode(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid armored keyring: %w", err)
		}
		entities, err := openpgp.ReadKeyRing(block.Body)
		if err != nil {
			return nil, fmt.Errorf("invalid armored keyring: %w", err)
		}
		keyring = append(keyring, entities...)
	}

	if len(keyring) == 0 {
		return nil, fmt.Errorf("invalid armored keyring: no keys found")
	}

	return &keyring, nil
}

func verifyReleaseSignature(keyring openpgp.EntityList, signed []byte, signature io.Reader) error {
	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(signed), signature, nil); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	return nil
}

func readLimited(ctx context.Context, url string) ([]byte, error) {
	reader, err := utils.DoGetRequestWithContext(ctx, url, debPackagesClient)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, maxInReleaseSize))
}

// if no keyring is provided, we will not verify anything
func fetchRelease(ctx context.Context, keyring *openpgp.EntityList, distURL string) ([]byte, error) {
	inRelease, err := readLimited(ctx, distURL+"InRelease")
	if err == nil && keyring != nil {
		signedRelease, _ := clearsign.Decode(inRelease)
		if signedRelease == nil {
			return nil, fmt.Errorf("%sInRelease: not signed", distURL)
		}

		if err := verifyReleaseSignature(*keyring, signedRelease.Bytes, signedRelease.ArmoredSignature.Body); err != nil {
			return nil, fmt.Errorf("%sInRelease: %w", distURL, err)
		}
		return signedRelease.Bytes, nil
	}

	release, err := readLimited(ctx, distURL+"Release")
	if err != nil {
		return nil, err
	}
	signature, err := readLimited(ctx, distURL+"Release.gpg")
	if err != nil && keyring != nil {
		// we were expecting it to exist and be valid, but it doesn't exist or is invalid
		return nil, fmt.Errorf("%sRelease.gpg: %w", distURL, err)
	} else if err != nil {
		// we don't have a keyring, so we can't verify the signature, but we can still return the release
		return release, nil
	}

	block, err := armor.Decode(bytes.NewReader(signature))
	if err != nil {
		return nil, fmt.Errorf("%sRelease.gpg: %w", distURL, err)
	}
	if err := verifyReleaseSignature(*keyring, release, block.Body); err != nil {
		return nil, fmt.Errorf("%sRelease: %w", distURL, err)
	}
	return release, nil
}

func DebPackageKey(pkg control.Paragraph) string {
	return pkg.Values["Package"] + "@" + pkg.Values["Version"]
}

func DebSnapshotPath(prefix string, snapshotTime time.Time) string {
	return prefix + "/" + snapshotTime.UTC().Format(MetasnapLayout)
}

var debPackagesClient = utils.NewEgressClient(5 * time.Minute)

// FetchDebPackages loads a suite's Packages index. The Release must be signed by armoredKeyring,
// or by the bundled debian keyring if armoredKeyring is empty.
func FetchDebPackages(ctx context.Context, registryConfig dtos.DebianRegistryConfig, archive, suite, component, arch string) (DebRelease, *control.ParagraphReader, error) {
	packagesPath := component + "/binary-" + arch + "/Packages.xz"
	distURL := registryConfig.GetURL() + "/" + archive + "/dists/" + suite + "/"

	keyring, err := parseArmoredKeyring(registryConfig.Keyring)
	if err != nil {
		return DebRelease{}, nil, err
	}

	releaseData, err := fetchRelease(ctx, keyring, distURL)
	if err != nil {
		return DebRelease{}, nil, err
	}

	var release DebRelease
	if err := control.Unmarshal(&release, bytes.NewReader(releaseData)); err != nil {
		return DebRelease{}, nil, err
	}

	fileHash, ok := release.File(packagesPath)
	if !ok {
		return DebRelease{}, nil, fmt.Errorf("%w: %s", ErrDebFileNotListed, packagesPath)
	}

	packagesReader, err := utils.DoGetRequestWithContext(ctx, distURL+packagesPath, debPackagesClient)
	if err != nil {
		return DebRelease{}, nil, err
	}
	defer packagesReader.Close()

	packagesData, err := io.ReadAll(io.LimitReader(packagesReader, MaxPackagesXZSize))
	if err != nil {
		return DebRelease{}, nil, err
	}

	if int64(len(packagesData)) != fileHash.Size {
		return DebRelease{}, nil, fmt.Errorf("size mismatch for %s", packagesPath)
	}

	verifier, err := fileHash.Verifier()
	if err != nil {
		return DebRelease{}, nil, err
	}
	if _, err := verifier.Write(packagesData); err != nil {
		return DebRelease{}, nil, err
	}
	if err := verifier.Close(); err != nil {
		return DebRelease{}, nil, fmt.Errorf("hash mismatch for %s: %w", packagesPath, err)
	}

	xzReader, err := xz.NewReader(bytes.NewReader(packagesData))
	if err != nil {
		return DebRelease{}, nil, fmt.Errorf("failed to create xz reader: %w", err)
	}

	paragraphReader, err := control.NewParagraphReader(xzReader, nil)
	if err != nil {
		return DebRelease{}, nil, fmt.Errorf("failed to create paragraph reader: %w", err)
	}
	return release, paragraphReader, nil
}
