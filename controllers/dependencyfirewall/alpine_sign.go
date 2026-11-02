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
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // apk signatures (.SIGN.RSA.*) are defined over sha1
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
)

const (
	alpineKeyPrefix = "devguard-dependency-proxy-"
	alpineKeySuffix = ".rsa.pub"
)

// apk looks the key up in /etc/apk/keys/ by the name in the signature entry. The fingerprint keeps keys of
// different secrets apart and gives a rotated key a new name.
func alpineKeyName(key *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	fingerprint := sha256.Sum256(der)
	return alpineKeyPrefix + hex.EncodeToString(fingerprint[:4]) + alpineKeySuffix, nil
}

func isAlpineKeyName(name string) bool {
	return strings.HasPrefix(name, alpineKeyPrefix) && strings.HasSuffix(name, alpineKeySuffix)
}

func (d *DependencyProxyController) alpineSigningKey(ctx context.Context, secret uuid.UUID) (*rsa.PrivateKey, error) {
	privateKey, _, err := d.dependencyProxyService.GetSigningKey(ctx, secret)
	if err != nil {
		return nil, err
	}
	return rsaKeyFromPGP(privateKey)
}

//go:embed alpine-keys/*.rsa.pub
var alpineKeyFiles embed.FS

// taken from aports main/alpine-keys
var alpineKeys = sync.OnceValues(func() ([]string, error) {
	files, err := fs.Glob(alpineKeyFiles, "alpine-keys/*.rsa.pub")
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(files))
	for _, name := range files {
		data, err := alpineKeyFiles.ReadFile(name)
		if err != nil {
			return nil, err
		}
		keys = append(keys, string(data))
	}
	return keys, nil
})

func defaultAlpineConfig() dtos.AlpineRegistryConfig {
	keys, err := alpineKeys()
	if err != nil {
		panic(fmt.Errorf("failed to load alpine keys: %w", err))
	}
	return dtos.AlpineRegistryConfig{URLRegistryConfig: dtos.URLRegistryConfig{URL: alpineRegistry}, Keys: keys}
}

func alpineRegistryConfig(configs DependencyProxyConfigs) dtos.AlpineRegistryConfig {
	if config := configs.Registries.AlpineConfig(); config != nil {
		return *config
	}
	return defaultAlpineConfig()
}

func splitAPKIndexArchive(data []byte) (signature, index []byte, err error) {
	reader := bytes.NewReader(data)
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open APKINDEX archive: %w", err)
	}
	gz.Multistream(false)
	header, err := tar.NewReader(gz).Next()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read APKINDEX archive: %w", err)
	}
	if !strings.HasPrefix(header.Name, ".SIGN.") {
		return nil, data, nil
	}
	// bytes.Reader is an io.ByteReader, so gzip does not read ahead past the end of the first stream
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return nil, nil, fmt.Errorf("failed to read APKINDEX signature: %w", err)
	}
	signatureLen := len(data) - reader.Len()
	return data[:signatureLen], data[signatureLen:], nil
}

func verifyAPKIndexSignature(signature, index []byte, pemKeys []string) error {
	if signature == nil {
		return fmt.Errorf("APKINDEX is not signed")
	}
	keys := make([]*rsa.PublicKey, 0, len(pemKeys))
	for _, pemKey := range pemKeys {
		key, err := dtos.ParseRSAPublicKey(pemKey)
		if err != nil {
			return fmt.Errorf("invalid alpine registry key: %w", err)
		}
		keys = append(keys, key)
	}

	sha1Digest := sha1.Sum(index) //nolint:gosec // see import
	sha256Digest := sha256.Sum256(index)

	gz, err := gzip.NewReader(bytes.NewReader(signature))
	if err != nil {
		return fmt.Errorf("failed to open APKINDEX signature: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		// the signature tar carries no end-of-archive marker
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("APKINDEX signature does not match any trusted key")
		}
		if err != nil {
			return fmt.Errorf("failed to read APKINDEX signature: %w", err)
		}

		var hash crypto.Hash
		var digest []byte
		switch {
		case strings.HasPrefix(header.Name, ".SIGN.RSA256."):
			hash, digest = crypto.SHA256, sha256Digest[:]
		case strings.HasPrefix(header.Name, ".SIGN.RSA."):
			hash, digest = crypto.SHA1, sha1Digest[:]
		default:
			continue
		}
		sig, err := io.ReadAll(io.LimitReader(tr, 4096))
		if err != nil {
			return fmt.Errorf("failed to read APKINDEX signature: %w", err)
		}
		for _, key := range keys {
			if rsa.VerifyPKCS1v15(key, hash, digest, sig) == nil {
				return nil
			}
		}
	}
}

func signAPKIndex(index []byte, key *rsa.PrivateKey) ([]byte, error) {
	digest := sha1.Sum(index) //nolint:gosec // see import
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest[:])
	if err != nil {
		return nil, err
	}
	keyName, err := alpineKeyName(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: ".SIGN.RSA." + keyName, Mode: 0644, Size: int64(len(sig)), Typeflag: tar.TypeReg, Uname: "root", Gname: "root"}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(sig); err != nil {
		return nil, err
	}
	// Flush instead of Close - like abuild-sign, the signature tar must not end with an end-of-archive marker,
	// otherwise apk stops reading before the index
	if err := tw.Flush(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func rsaKeyFromPGP(armoredPrivateKey string) (*rsa.PrivateKey, error) {
	key, err := pgpcrypto.NewKeyFromArmored(armoredPrivateKey)
	if err != nil {
		return nil, err
	}
	entity := key.GetEntity()
	if entity == nil || entity.PrivateKey == nil {
		return nil, fmt.Errorf("signing key has no private key")
	}
	rsaKey, ok := entity.PrivateKey.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key is not an RSA key")
	}
	return rsaKey, nil
}

func alpinePublicKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
