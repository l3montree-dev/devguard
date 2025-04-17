package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/pkg/errors"
)

// containsRune checks if a string contains a specific rune
func containsRune(s string, r rune) bool {
	for _, char := range s {
		if char == r {
			return true
		}
	}
	return false
}

func sanitizeApiUrl(apiUrl string) string {
	// check if the url has a trailing slash
	apiUrl = strings.TrimSuffix(apiUrl, "/")

	// check if the url has a protocol
	if !strings.HasPrefix(apiUrl, "http://") && !strings.HasPrefix(apiUrl, "https://") {
		apiUrl = "https://" + apiUrl
	}

	return apiUrl
}

// IsValidPath checks if a string is a valid file path
func isValidPath(path string) error {
	// Check for null bytes
	if !utf8.ValidString(path) || len(path) == 0 {
		return fmt.Errorf("path contains null bytes")
	}

	// Check for invalid characters
	invalidChars := `<>:"\|?*`
	for _, char := range invalidChars {
		if containsRune(path, char) {
			return fmt.Errorf("invalid character '%c' in path", char)
		}
	}

	// Check if the path length is within the acceptable limit
	if len(path) > 260 {
		return fmt.Errorf("path length exceeds 260 characters")
	}

	// Check if the path is either absolute or relative
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	// Check if the path exists
	_, err = os.Stat(absPath)

	if os.IsNotExist(err) {
		return errors.Wrap(err, "path does not exist: %s"+absPath)
	}

	return nil
}
