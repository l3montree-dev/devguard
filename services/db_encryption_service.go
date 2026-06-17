package services

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

const KeyFilePathENVName = "APP_SIDE_ENCRYPTION_KEY_PATH"

// use a versioned prefix to tell cipher text apart from plaintext
const encryptionPrefix = "dgenc:v1:"

type DBEncryptionService struct {
	mu  sync.RWMutex
	gcm cipher.AEAD // the gcm module to encrypt and decrypt using the provided key
}

func NewDBEncryptionService() *DBEncryptionService {
	return &DBEncryptionService{}
}

// builds a service from an explicit key; used for the key rotation
func NewDBEncryptionServiceFromKey(key []byte) (*DBEncryptionService, error) {
	gcm, err := buildGCM(key)
	if err != nil {
		return nil, fmt.Errorf("could not build new encryption service from key: %w", err)
	}
	return &DBEncryptionService{gcm: gcm}, nil
}

// eagerly loads the key on startup so misconfiguration fails fast; lazy loading covers callers that skip this
// nosemgrep: service-method-missing-ctx,service-method-missing-ctx-empty-params -- startup helper; no request context available
func (service *DBEncryptionService) LoadDBEncryptionKey() {
	if _, err := service.loadGCM(); err != nil {
		panic(err.Error())
	}
	slog.Info("successfully loaded encryption key")
}

// loadGCM returns the gcm, lazily building it from the key file on first use so the service is usable
// in every fx app that provides it, not only those that call LoadDBEncryptionKey on startup
// nosemgrep: service-method-missing-ctx,service-method-missing-ctx-empty-params -- private crypto helper; no I/O
func (service *DBEncryptionService) loadGCM() (cipher.AEAD, error) {
	service.mu.RLock()
	gcm := service.gcm
	service.mu.RUnlock()
	if gcm != nil {
		return gcm, nil
	}

	service.mu.Lock()
	defer service.mu.Unlock()
	if service.gcm != nil {
		return service.gcm, nil
	}

	key, err := readCurrentKey()
	if err != nil {
		return nil, err
	}
	gcm, err = buildGCM(key)
	if err != nil {
		return nil, err
	}
	service.gcm = gcm
	return gcm, nil
}

// reads the current key from the key file specified in the .env file, panicking if it is unavailable
func ReadCurrentKey() []byte {
	key, err := readCurrentKey()
	if err != nil {
		panic(err.Error())
	}
	return key
}

func readCurrentKey() ([]byte, error) {
	keyPath := os.Getenv(KeyFilePathENVName)
	if keyPath == "" {
		return nil, fmt.Errorf("could not resolve encryption key path. Make sure to have the env variable '%s' set in your .env. See the .env.example for the default path and more instructions", KeyFilePathENVName)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not open key file for app side encryption. Make sure that the file exists and matches the environment variable '%s'. For more information read the .env-example. Found the following path in the env variable: %s: %w", KeyFilePathENVName, keyPath, err)
	}
	return key, nil
}

// validates the hex encoded key and builds the AES-GCM cipher from it
func buildGCM(key []byte) (cipher.AEAD, error) {
	key = bytes.TrimSpace(key)

	decodedKey := make([]byte, hex.DecodedLen(len(key)))
	n, err := hex.Decode(decodedKey, key)
	if err != nil {
		return nil, fmt.Errorf("could not hex decode the key; it needs to be a hex encoded 256 bit AES key (64 hex characters): %w", err)
	}
	decodedKey = decodedKey[:n]
	if len(decodedKey) != 32 {
		return nil, fmt.Errorf("invalid key format; the key needs to be exactly 256 bit in size (64 hex characters)")
	}

	aesCipher, err := aes.NewCipher(decodedKey)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher using the loaded key: %w", err)
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("could not create GCM cipher using the AES cipher: %w", err)
	}

	return gcm, nil
}

// returns the data untouched if it carries no encryption prefix (plaintext) and otherwise strips the prefix and decrypts.
// nosemgrep: service-method-missing-ctx -- pure crypto; no I/O, interface constraint prevents ctx addition
func (service *DBEncryptionService) MaybeDecryptData(data string) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	// check if the data is encrypted (or plaintext otherwise)
	if !strings.HasPrefix(data, encryptionPrefix) {
		return data, nil
	}

	return service.decryptData(strings.TrimPrefix(data, encryptionPrefix))
}

// decrypts a base64 encoded nonce+ciphertext blob using the loaded key
// nosemgrep: service-method-missing-ctx -- private crypto helper; no I/O
func (service *DBEncryptionService) decryptData(data string) (string, error) {
	gcm, err := service.loadGCM()
	if err != nil {
		return "", fmt.Errorf("could not load encryption key: %w", err)
	}

	rawData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode the encrypted data: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(rawData) < nonceSize+gcm.Overhead() {
		return "", fmt.Errorf("invalid data format;unable to decrypt")
	}

	nonce, ciphertext := rawData[:nonceSize], rawData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("could not decrypt the data: %w", err)
	}

	return string(plaintext), nil
}

// encrypts the data using AES-GCM and the loaded key and wraps it inside the encryption format (enc prefix+nonce+cipher)
// nosemgrep: service-method-missing-ctx -- pure crypto; no I/O, interface constraint prevents ctx addition
func (service *DBEncryptionService) EncryptAndWrapData(data string) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	gcm, err := service.loadGCM()
	if err != nil {
		return "", fmt.Errorf("could not load encryption key: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", fmt.Errorf("could not generate a new nonce from random pool: %w", err)
	}

	// prepend the nonce to the encrypted text
	encryptedData := gcm.Seal(nonce, nonce, []byte(data), nil)

	return encryptionPrefix + base64.StdEncoding.EncodeToString(encryptedData), nil
}
