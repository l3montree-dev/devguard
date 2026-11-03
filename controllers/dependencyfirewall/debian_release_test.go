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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pault.ag/go/debian/control"
)

func debSigningKey(t *testing.T) (privateKey string, publicKey openpgp.EntityList) {
	key, err := crypto.PGPWithProfile(profile.RFC4880()).KeyGeneration().AddUserId("DevGuard Dependency Proxy", "noreply@devguard.org").New().GenerateKey()
	require.NoError(t, err)
	privateKey, err = key.Armor()
	require.NoError(t, err)
	armoredPublicKey, err := key.GetArmoredPublicKey()
	require.NoError(t, err)
	publicKey, err = openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPublicKey))
	require.NoError(t, err)
	return privateKey, publicKey
}

func debSHA256(filename string, data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%s %d %s", hex.EncodeToString(hash[:]), len(data), filename)
}

func TestSignDebRelease(t *testing.T) {
	privateKey, publicKey := debSigningKey(t)
	releaseText := []byte("Origin: Debian\nSuite: stable\nCodename: trixie\nSHA256:\n abc 1 main/binary-amd64/Packages\n")

	inRelease, releaseGPG, err := signDebRelease(releaseText, privateKey)
	require.NoError(t, err)

	t.Run("InRelease is a clearsigned Release verifiable with the public key", func(t *testing.T) {
		block, rest := clearsign.Decode(inRelease)
		require.NotNil(t, block)
		assert.Empty(t, bytes.TrimSpace(rest))
		assert.Equal(t, string(releaseText), string(block.Plaintext))
		_, err := openpgp.CheckDetachedSignature(publicKey, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil)
		assert.NoError(t, err)
	})

	t.Run("Release.gpg is a detached signature over the Release", func(t *testing.T) {
		block, err := armor.Decode(bytes.NewReader(releaseGPG))
		require.NoError(t, err)
		_, err = openpgp.CheckDetachedSignature(publicKey, bytes.NewReader(releaseText), block.Body, nil)
		assert.NoError(t, err)
	})

	t.Run("Release.gpg does not verify a tampered Release", func(t *testing.T) {
		block, err := armor.Decode(bytes.NewReader(releaseGPG))
		require.NoError(t, err)
		tampered := bytes.Replace(releaseText, []byte("abc"), []byte("def"), 1)
		_, err = openpgp.CheckDetachedSignature(publicKey, bytes.NewReader(tampered), block.Body, nil)
		assert.Error(t, err)
	})

	t.Run("Release.gpg does not verify with another key", func(t *testing.T) {
		_, otherPublicKey := debSigningKey(t)
		block, err := armor.Decode(bytes.NewReader(releaseGPG))
		require.NoError(t, err)
		_, err = openpgp.CheckDetachedSignature(otherPublicKey, bytes.NewReader(releaseText), block.Body, nil)
		assert.Error(t, err)
	})

	t.Run("invalid private key", func(t *testing.T) {
		_, _, err := signDebRelease(releaseText, "not a key")
		assert.Error(t, err)
	})
}

func TestUpdateDebRelease(t *testing.T) {
	release := shared.DebRelease{
		Paragraph: control.Paragraph{
			Values: map[string]string{
				"Origin":   "Debian",
				"Codename": "trixie",
				"MD5Sum":   "\n 0 1 main/binary-amd64/Packages",
				"SHA1":     "\n 0 1 main/binary-amd64/Packages",
				"SHA256":   "\n upstream",
			},
			Order: []string{"Origin", "Codename", "MD5Sum", "SHA1", "SHA256"},
		},
		SHA256: []control.SHA256FileHash{
			{FileHash: control.FileHash{Hash: "upstream-packages", Size: 10, Filename: "main/binary-amd64/Packages"}},
			{FileHash: control.FileHash{Hash: "upstream-packages-xz", Size: 5, Filename: "main/binary-amd64/Packages.xz"}},
			{FileHash: control.FileHash{Hash: "upstream-contents", Size: 7, Filename: "main/Contents-amd64"}},
		},
	}
	files := map[string][]byte{
		"main/binary-amd64/Packages":    []byte("Package: curl\n"),
		"main/binary-amd64/Packages.xz": []byte("xz"),
	}

	updated := updateDebRelease(release, files)

	assert.Equal(t, strings.Join([]string{
		"upstream-contents 7 main/Contents-amd64",
		debSHA256("main/binary-amd64/Packages", files["main/binary-amd64/Packages"]),
		debSHA256("main/binary-amd64/Packages.xz", files["main/binary-amd64/Packages.xz"]),
	}, "\n"), updated.Values["SHA256"])
	assert.NotContains(t, updated.Values, "MD5Sum")
	assert.NotContains(t, updated.Values, "SHA1")
	assert.Equal(t, []string{"Origin", "Codename", "SHA256"}, updated.Order)
	assert.Equal(t, "trixie", updated.Values["Codename"])

	// the upstream release is left untouched
	assert.Contains(t, release.Values, "MD5Sum")
	assert.Equal(t, "\n upstream", release.Values["SHA256"])
}
