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
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
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

var debianKeyring = sync.OnceValues(func() (openpgp.EntityList, error) {
	files, err := fs.Glob(debianKeyringFiles, "debian-keyring/*.asc")
	if err != nil {
		return nil, err
	}

	var keyring openpgp.EntityList
	for _, name := range files {
		data, err := debianKeyringFiles.ReadFile(name)
		if err != nil {
			return nil, err
		}
		entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", name, err)
		}
		keyring = append(keyring, entities...)
	}
	return keyring, nil
})

var ErrDebFileNotListed = errors.New("file not listed in InRelease")

func IsDebianRegistry(registry string) bool {
	return registry == DebRegistry || registry == DebSnapshotRegistry
}

func verifyDebianSignature(signedRelease *clearsign.Block) error {
	if signedRelease == nil {
		return errors.New("not signed")
	}

	keyring, err := debianKeyring()
	if err != nil {
		return err
	}
	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(signedRelease.Bytes), signedRelease.ArmoredSignature.Body, nil); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	return nil
}

func DebPackageKey(pkg control.Paragraph) string {
	return pkg.Values["Package"] + "@" + pkg.Values["Version"]
}

func DebSnapshotPath(prefix string, snapshotTime time.Time) string {
	return prefix + "/" + snapshotTime.UTC().Format(MetasnapLayout)
}

var debPackagesClient = utils.NewEgressClient(5 * time.Minute)

func FetchDebPackages(ctx context.Context, registry, archive, suite, component, arch string) (DebRelease, *control.ParagraphReader, error) {
	packagesPath := component + "/binary-" + arch + "/Packages.xz"
	distURL := registry + "/" + archive + "/dists/" + suite + "/"

	releaseReader, err := utils.DoGetRequestWithContext(ctx, distURL+"InRelease", debPackagesClient)
	if err != nil {
		return DebRelease{}, nil, err
	}
	defer releaseReader.Close()

	releaseData, err := io.ReadAll(io.LimitReader(releaseReader, maxInReleaseSize))
	if err != nil {
		return DebRelease{}, nil, err
	}

	signedRelease, _ := clearsign.Decode(releaseData)
	if IsDebianRegistry(registry) {
		if err := verifyDebianSignature(signedRelease); err != nil {
			return DebRelease{}, nil, fmt.Errorf("%sInRelease: %w", distURL, err)
		}
	}
	if signedRelease != nil {
		releaseData = signedRelease.Bytes
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
