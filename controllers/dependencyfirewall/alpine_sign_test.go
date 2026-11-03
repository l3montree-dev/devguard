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
	"archive/tar"
	"testing"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlpineIndexSignature(t *testing.T) {
	pgpKey, err := pgpcrypto.PGPWithProfile(profile.RFC4880()).KeyGeneration().AddUserId("test", "test@example.com").New().GenerateKey()
	require.NoError(t, err)
	armored, err := pgpKey.Armor()
	require.NoError(t, err)

	rsaKey, err := rsaKeyFromPGP(armored)
	require.NoError(t, err)

	keyName, err := alpineKeyName(&rsaKey.PublicKey)
	require.NoError(t, err)
	assert.Regexp(t, `^devguard-dependency-proxy-[0-9a-f]{8}\.rsa\.pub$`, keyName)
	assert.True(t, isAlpineKeyName(keyName))
	publicKey, err := alpinePublicKeyPEM(rsaKey)
	require.NoError(t, err)

	index, err := writeAPKIndexTar([]tarEntry{
		{header: &tar.Header{Name: "DESCRIPTION", Mode: 0644, Typeflag: tar.TypeReg}, data: []byte("v3.20.0")},
		{header: &tar.Header{Name: "APKINDEX", Mode: 0644, Typeflag: tar.TypeReg}, data: []byte("P:curl\nV:8.14.1-r0\nt:1700000000\n\n")},
	})
	require.NoError(t, err)
	signature, err := signAPKIndex(index, rsaKey)
	require.NoError(t, err)

	t.Run("signed archive splits and verifies", func(t *testing.T) {
		gotSignature, gotIndex, err := splitAPKIndexArchive(append(append([]byte{}, signature...), index...))
		require.NoError(t, err)
		assert.Equal(t, signature, gotSignature)
		assert.Equal(t, index, gotIndex)
		assert.NoError(t, verifyAPKIndexSignature(gotSignature, gotIndex, []string{string(publicKey)}))

		entries, err := readAPKIndexTar(gotIndex)
		require.NoError(t, err)
		assert.Len(t, entries, 2)
	})

	t.Run("tampered index does not verify", func(t *testing.T) {
		tampered, err := writeAPKIndexTar([]tarEntry{
			{header: &tar.Header{Name: "APKINDEX", Mode: 0644, Typeflag: tar.TypeReg}, data: []byte("P:evil\nV:1.0-r0\n\n")},
		})
		require.NoError(t, err)
		assert.Error(t, verifyAPKIndexSignature(signature, tampered, []string{string(publicKey)}))
	})

	t.Run("other key does not verify", func(t *testing.T) {
		keys, err := alpineKeys()
		require.NoError(t, err)
		assert.Error(t, verifyAPKIndexSignature(signature, index, keys))
	})

	t.Run("unsigned archive has no signature", func(t *testing.T) {
		gotSignature, gotIndex, err := splitAPKIndexArchive(index)
		require.NoError(t, err)
		assert.Nil(t, gotSignature)
		assert.Equal(t, index, gotIndex)
		assert.Error(t, verifyAPKIndexSignature(gotSignature, gotIndex, []string{string(publicKey)}))
	})
}

func TestAlpineKeysAreEmbedded(t *testing.T) {
	keys, err := alpineKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 18)
	for _, key := range keys {
		_, err := dtos.ParseRSAPublicKey(key)
		assert.NoError(t, err)
	}
}
