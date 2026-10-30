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

package dependencyfirewall

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/ulikunitz/xz"
	"pault.ag/go/debian/control"
)

func writeDebPackages(packages []shared.DebPackage) (raw, xzData, gzData []byte, err error) {
	var rawBuf, xzBuf, gzBuf bytes.Buffer
	xzWriter, err := xz.NewWriter(&xzBuf)
	if err != nil {
		return nil, nil, nil, err
	}
	gzWriter := gzip.NewWriter(&gzBuf)
	out := io.MultiWriter(&rawBuf, xzWriter, gzWriter)

	for _, pkg := range packages {
		if err := pkg.Paragraph.WriteTo(out); err != nil {
			return nil, nil, nil, err
		}
		if _, err := io.WriteString(out, "\n"); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := xzWriter.Close(); err != nil {
		return nil, nil, nil, err
	}
	if err := gzWriter.Close(); err != nil {
		return nil, nil, nil, err
	}
	return rawBuf.Bytes(), xzBuf.Bytes(), gzBuf.Bytes(), nil
}

func updateDebRelease(release shared.DebRelease, files map[string][]byte) control.Paragraph {
	var lines []string
	for _, entry := range release.SHA256 {
		if strings.Contains(entry.Filename, "/binary-") && strings.Contains(entry.Filename, "/Packages") {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %d %s", entry.Hash, entry.Size, entry.Filename))
	}
	for _, filePath := range slices.Sorted(maps.Keys(files)) {
		hash := sha256.Sum256(files[filePath])
		lines = append(lines, fmt.Sprintf("%s %d %s", hex.EncodeToString(hash[:]), len(files[filePath]), filePath))
	}

	values := maps.Clone(release.Values)
	values["SHA256"] = strings.Join(lines, "\n")
	delete(values, "MD5Sum")
	delete(values, "SHA1")

	order := slices.DeleteFunc(slices.Clone(release.Order), func(key string) bool {
		return key == "MD5Sum" || key == "SHA1"
	})
	return control.Paragraph{Values: values, Order: order}
}

func signDebRelease(releaseText []byte, privateKey string) (inRelease, releaseGPG []byte, err error) {
	key, err := crypto.NewKeyFromArmored(privateKey)
	if err != nil {
		return nil, nil, err
	}

	pgp := crypto.PGPWithProfile(profile.RFC4880())

	clearSigner, err := pgp.Sign().SigningKey(key).New()
	if err != nil {
		return nil, nil, err
	}
	inRelease, err = clearSigner.SignCleartext(releaseText)
	if err != nil {
		return nil, nil, err
	}

	detachedSigner, err := pgp.Sign().SigningKey(key).Detached().New()
	if err != nil {
		return nil, nil, err
	}
	releaseGPG, err = detachedSigner.Sign(releaseText, crypto.Armor)
	if err != nil {
		return nil, nil, err
	}

	return inRelease, releaseGPG, nil
}
