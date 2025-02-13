package intotocmd

import "testing"

func TestRedactSecret(t *testing.T) {

	t.Run("RedactSecret", func(t *testing.T) {
		testStr := "devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --token=20b232bf8fde72ebdc2e6e7fe599de4325bdad71b555e2d35e7df8783b4e4e54 --apiUrl=https://api.main.devguard.org"

		redactedStr := redactSecrets(testStr)

		if redactedStr != "devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --REDACTED --apiUrl=https://api.main.devguard.org" {
			t.Errorf("Expected: devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --REDACTED --apiUrl=https://api.main.devguard.org, got: %s", redactedStr)
		}
	})

	t.Run("RedactSecret in map", func(t *testing.T) {
		result := cleanMap(map[string]interface{}{
			"INPUT_ARGS": "devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --token=20b232bf8fde72ebdc2e6e7fe599de4325bdad71b555e2d35e7df8783b4e4e54 --apiUrl=https://api.main.devguard.org",
		})

		if result["INPUT_ARGS"] != "devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --REDACTED --apiUrl=https://api.main.devguard.org" {
			t.Errorf("Expected: devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --REDACTED --apiUrl=https://api.main.devguard.org, got: %s", result["INPUT_ARGS"])
		}
	})
}
