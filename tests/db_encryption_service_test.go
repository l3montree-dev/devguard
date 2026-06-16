package tests

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// an example 256 bit AES key
const testEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// mirrors the unexported prefix in the service; kept here so a format change makes these tests fail on purpose
const testEncryptionPrefix = "dgenc:v1:"

func TestEncryptAndWrapData(t *testing.T) {
	enc, err := services.NewDBEncryptionServiceFromKey([]byte(testEncryptionKey))
	require.NoError(t, err)

	t.Run("encrypts and decrypts back to the original plaintext", func(t *testing.T) {
		plaintext := "glpat-super-secret-token"

		encrypted, err := enc.EncryptAndWrapData(plaintext)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, encrypted)
		assert.True(t, strings.HasPrefix(encrypted, testEncryptionPrefix), "ciphertext must carry the versioned prefix")

		decrypted, err := enc.MaybeDecryptData(encrypted)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypting empty data returns empty without a prefix", func(t *testing.T) {
		encrypted, err := enc.EncryptAndWrapData("")
		require.NoError(t, err)
		assert.Equal(t, "", encrypted)
	})

	t.Run("produces a different ciphertext each time but decrypts to the same plaintext", func(t *testing.T) {
		plaintext := "the same secret"

		first, err := enc.EncryptAndWrapData(plaintext)
		require.NoError(t, err)
		second, err := enc.EncryptAndWrapData(plaintext)
		require.NoError(t, err)

		assert.NotEqual(t, first, second, "a fresh nonce must make every ciphertext unique")

		firstDecrypted, err := enc.MaybeDecryptData(first)
		require.NoError(t, err)
		secondDecrypted, err := enc.MaybeDecryptData(second)
		require.NoError(t, err)
		assert.Equal(t, plaintext, firstDecrypted)
		assert.Equal(t, plaintext, secondDecrypted)
	})

	t.Run("round trips unicode and long values", func(t *testing.T) {
		plaintext := strings.Repeat("test123-", 500)

		encrypted, err := enc.EncryptAndWrapData(plaintext)
		require.NoError(t, err)

		decrypted, err := enc.MaybeDecryptData(encrypted)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

func TestMaybeDecryptData(t *testing.T) {
	enc, err := services.NewDBEncryptionServiceFromKey([]byte(testEncryptionKey))
	require.NoError(t, err)

	t.Run("returns empty data untouched", func(t *testing.T) {
		decrypted, err := enc.MaybeDecryptData("")
		require.NoError(t, err)
		assert.Equal(t, "", decrypted)
	})

	t.Run("returns plaintext without the prefix untouched", func(t *testing.T) {
		plaintext := "plain-old-token-from-before-encryption"
		decrypted, err := enc.MaybeDecryptData(plaintext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("fails on tampered ciphertext", func(t *testing.T) {
		encrypted, err := enc.EncryptAndWrapData("authenticated secret")
		require.NoError(t, err)

		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encrypted, testEncryptionPrefix))
		require.NoError(t, err)
		raw[len(raw)-1] ^= 0xff // flip the last ciphertext byte to break the GCM auth tag
		tampered := testEncryptionPrefix + base64.StdEncoding.EncodeToString(raw)

		_, err = enc.MaybeDecryptData(tampered)
		assert.Error(t, err)
	})

	t.Run("fails on prefixed but non base64 data", func(t *testing.T) {
		_, err := enc.MaybeDecryptData(testEncryptionPrefix + "not-valid-base64!!!")
		assert.Error(t, err)
	})

	t.Run("fails when prefixed data is too short to hold a nonce", func(t *testing.T) {
		tooShort := testEncryptionPrefix + base64.StdEncoding.EncodeToString([]byte("short"))
		_, err := enc.MaybeDecryptData(tooShort)
		assert.Error(t, err)
	})

	t.Run("cannot decrypt data encrypted with a different key", func(t *testing.T) {
		encrypted, err := enc.EncryptAndWrapData("secret for key A")
		require.NoError(t, err)

		otherKey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
		otherEnc, err := services.NewDBEncryptionServiceFromKey([]byte(otherKey))
		require.NoError(t, err)

		_, err = otherEnc.MaybeDecryptData(encrypted)
		assert.Error(t, err)
	})
}

func TestNewDBEncryptionServiceFromKey(t *testing.T) {
	t.Run("accepts a valid hex encoded 256 bit key", func(t *testing.T) {
		_, err := services.NewDBEncryptionServiceFromKey([]byte(testEncryptionKey))
		assert.NoError(t, err)
	})

	t.Run("trims surrounding whitespace from the key", func(t *testing.T) {
		_, err := services.NewDBEncryptionServiceFromKey([]byte("  " + testEncryptionKey + "\n"))
		assert.NoError(t, err)
	})

	t.Run("rejects a non hex key", func(t *testing.T) {
		_, err := services.NewDBEncryptionServiceFromKey([]byte(strings.Repeat("zz", 32)))
		assert.Error(t, err)
	})

	t.Run("rejects a key of the wrong length", func(t *testing.T) {
		_, err := services.NewDBEncryptionServiceFromKey([]byte("0123456789abcdef"))
		assert.Error(t, err)
	})
}

// covers the lazy load path: a service built without an explicit key resolves it from the key file on first use
func TestDBEncryptionServiceLazyLoad(t *testing.T) {
	t.Run("loads the key from the configured file on first use", func(t *testing.T) {
		keyPath := filepath.Join(t.TempDir(), "encryption.key")
		require.NoError(t, os.WriteFile(keyPath, []byte(testEncryptionKey), 0600))
		t.Setenv(services.KeyFilePathENVName, keyPath)

		enc := services.NewDBEncryptionService()

		encrypted, err := enc.EncryptAndWrapData("lazily encrypted")
		require.NoError(t, err)

		decrypted, err := enc.MaybeDecryptData(encrypted)
		require.NoError(t, err)
		assert.Equal(t, "lazily encrypted", decrypted)
	})

	t.Run("returns an error instead of panicking when the key path is not configured", func(t *testing.T) {
		t.Setenv(services.KeyFilePathENVName, "")

		enc := services.NewDBEncryptionService()

		_, err := enc.EncryptAndWrapData("no key available")
		assert.Error(t, err)
	})

	t.Run("returns an error when the key file is missing", func(t *testing.T) {
		t.Setenv(services.KeyFilePathENVName, filepath.Join(t.TempDir(), "does-not-exist.key"))

		enc := services.NewDBEncryptionService()

		_, err := enc.EncryptAndWrapData("no key file")
		assert.Error(t, err)
	})

	// guards the double checked locking in loadGCM against concurrent first use
	t.Run("is safe for concurrent first use", func(t *testing.T) {
		keyPath := filepath.Join(t.TempDir(), "encryption.key")
		require.NoError(t, os.WriteFile(keyPath, []byte(testEncryptionKey), 0600))
		t.Setenv(services.KeyFilePathENVName, keyPath)

		enc := services.NewDBEncryptionService()

		const goroutines = 50
		errs := make(chan error, goroutines)
		for range goroutines {
			go func() {
				encrypted, err := enc.EncryptAndWrapData("concurrent secret")
				if err != nil {
					errs <- err
					return
				}
				_, err = enc.MaybeDecryptData(encrypted)
				errs <- err
			}()
		}

		for range goroutines {
			require.NoError(t, <-errs)
		}
	})
}
