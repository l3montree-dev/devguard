package services

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"os"
)

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
	keyPath := os.Getenv("APP_SIDE_ENCRYPTION_KEY_PATH")
	if keyPath == "" {
		panic("could not resolve encryption key path. Make sure to have the env variable 'APP_SIDE_ENCRYPTION_KEY_PATH' set in your .env. See the .env-example for the default path.")
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		panic(fmt.Sprintf("could not open key file for app side encryption. Make sure that the file exists and matches the environment variable 'APP_SIDE_ENCRYPTION_KEY_PATH'.\nFound the following path in the env variable: %s. Ran into the following error: %s", keyPath, err.Error()))
	}

	gcm, err := buildGCM(key)
	if err != nil {
		panic(err.Error())
	}

	service.gcm = gcm
	slog.Info("successfully loaded encryption key")
}

// validates the key and builds the AES-GCM cipher from it
func buildGCM(key []byte) (cipher.AEAD, error) {
	key = bytes.TrimSpace(key)
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key format; the key needs to be exactly 256 bit in size")
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher using the loaded key: %w", err)
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("could not create GCM cipher using the AES cipher: %w", err)
	}

	return gcm, nil
}

// checks if the data is encrypted (wrapped) and decrypts if its the case
func (service *DBEncryptionService) MaybeDecryptData(data string) (string, error) {
	if len(data) == 0 {
		return "", nil
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

	nonce := make([]byte, service.gcm.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", fmt.Errorf("could not generate a new nonce from random pool: %w", err)
	}

	// prepend the nonce to the encrypted text
	encryptedData := service.gcm.Seal(nonce, nonce, []byte(data), nil)

	return base64.StdEncoding.EncodeToString(encryptedData), nil
}
