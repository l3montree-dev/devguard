package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"os"
)

type DBEncryptionService struct {
	key []byte
}

func NewDBEncryptionService() *DBEncryptionService {
	return &DBEncryptionService{}
}

func (service *DBEncryptionService) LoadDBEncryptionKey() {
	keyPath := os.Getenv("APP_SIDE_ENCRYPTION_KEY_PATH")
	if keyPath == "" {
		panic("could not resolve encryption key path. Make sure to have the env variable 'APP_SIDE_ENCRYPTION_KEY_PATH' set in your .env. See the .env-example for the default path.")
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		panic(fmt.Sprintf("could not open key file for app side encryption. Make sure that the file exists and matches the environment variable 'APP_SIDE_ENCRYPTION_KEY_PATH'.\nFound the following path in the env variable: %s. Ran into the following error: %w", keyPath, err))
	}
	service.key = key
	slog.Info("successfully loaded encryption key")
}

// checks if the data is encrypted (wrapped) and decrypts if its the case
func (service *DBEncryptionService) MaybeDecryptData(data string) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	aesCipher, err := aes.NewCipher(service.key)
	if err != nil {
		return "", fmt.Errorf("could not create AES cipher using existing key: %w", err)
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return "", fmt.Errorf("could not create GCM cipher using AES cipher: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("invalid data format;unable to decrypt")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
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

	aesCipher, err := aes.NewCipher(service.key)
	if err != nil {
		return "", fmt.Errorf("could not create AES cipher using existing key: %w", err)
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return "", fmt.Errorf("could not create GCM cipher using AES cipher: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", fmt.Errorf("could not generate a new nonce from random pool: %w", err)
	}

	encryptedData := gcm.Seal(nil, nonce, []byte(data), nil)
	if len(encryptedData) == 0 {
		return "", fmt.Errorf("could not successfully encrypt the provided data")
	}
	return string(encryptedData), nil
}
