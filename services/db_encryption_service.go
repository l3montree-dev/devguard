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
)

const KeyFilePathENVName = "APP_SIDE_ENCRYPTION_KEY_PATH"

// use a versioned prefix to tell cipher text apart from plaintext
const encryptionPrefix = "dgenc:v1:"

type DBEncryptionService struct {
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

// load the key and build the gcm from it on start up once; then reuse it for every operation
func (service *DBEncryptionService) LoadDBEncryptionKey() {
	key := ReadCurrentKey()

	gcm, err := buildGCM(key)
	if err != nil {
		panic(err.Error())
	}

	service.gcm = gcm
	slog.Info("successfully loaded encryption key")
}

func ReadCurrentKey() []byte {
	keyPath := os.Getenv(KeyFilePathENVName)
	if keyPath == "" {
		panic(fmt.Sprintf("could not resolve encryption key path. Make sure to have the env variable '%s' set in your .env. See the .env-example for the default path.", KeyFilePathENVName))
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		panic(fmt.Sprintf("could not open key file for app side encryption. Make sure that the file exists and matches the environment variable '%s'.\nFound the following path in the env variable: %s. Ran into the following error: %s", KeyFilePathENVName, keyPath, err.Error()))
	}
	return key
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
func (service *DBEncryptionService) MaybeDecryptData(data string) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	if !strings.HasPrefix(data, encryptionPrefix) {
		return data, nil
	}

	return service.decryptData(strings.TrimPrefix(data, encryptionPrefix))
}

// decrypts a base64 encoded nonce+ciphertext blob using the loaded key
func (service *DBEncryptionService) decryptData(data string) (string, error) {
	if service.gcm == nil {
		return "", fmt.Errorf("encryption key not loaded; cannot decrypt data")
	}

	rawData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode the encrypted data: %w", err)
	}

	nonceSize := service.gcm.NonceSize()
	if len(rawData) < nonceSize+service.gcm.Overhead() {
		return "", fmt.Errorf("invalid data format;unable to decrypt")
	}

	nonce, ciphertext := rawData[:nonceSize], rawData[nonceSize:]
	plaintext, err := service.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("could not decrypt the data: %w", err)
	}

	return string(plaintext), nil
}

// encrypts the data using AES-GCM and the loaded key and wraps it inside the encryption format
func (service *DBEncryptionService) EncryptAndWrapData(data string) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	if service.gcm == nil {
		return "", fmt.Errorf("encryption key not loaded; cannot encrypt data")
	}

	nonce := make([]byte, service.gcm.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", fmt.Errorf("could not generate a new nonce from random pool: %w", err)
	}

	// prepend the nonce to the encrypted text
	encryptedData := service.gcm.Seal(nonce, nonce, []byte(data), nil)

	return encryptionPrefix + base64.StdEncoding.EncodeToString(encryptedData), nil
}
