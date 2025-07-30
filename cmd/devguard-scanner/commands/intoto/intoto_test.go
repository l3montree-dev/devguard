package intotocmd

import "testing"

func setEmptyEnvVars(t *testing.T) {
	// Clear the environment variables to avoid conflicts
	t.Setenv("CI_COMMIT_REF_NAME", "")
	t.Setenv("CI_DEFAULT_BRANCH", "")
	t.Setenv("CI_COMMIT_TAG", "")
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("GITHUB_BASE_REF", "")
}

func TestRedactSecret(t *testing.T) {

	setEmptyEnvVars(t)

	t.Run("RedactSecret", func(t *testing.T) {
		testStr := "devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --token=20b232bf8fde72ebdc2e6e7fe599de4325bdad71b555e2d35e7df8783b4e4e54 --apiURL=https://api.devguard.org"

		redactedStr := redactSecrets(testStr)

		if redactedStr != "devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --REDACTED --apiURL=https://api.devguard.org" {
			t.Errorf("Expected: devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --REDACTED --apiURL=https://api.devguard.org, got: %s", redactedStr)
		}
	})

	t.Run("RedactSecret in map", func(t *testing.T) {
		result := removeSecretsFromMap(map[string]interface{}{
			"INPUT_ARGS": "devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --token=20b232bf8fde72ebdc2e6e7fe599de4325bdad71b555e2d35e7df8783b4e4e54 --apiURL=https://api.devguard.org",
		})

		if result["INPUT_ARGS"] != "devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --REDACTED --apiURL=https://api.devguard.org" {
			t.Errorf("Expected: devguard-scanner intoto stop --step=build --products=image-digest.txt --products=image-tag.txt --products=image-tag.txt --REDACTED --apiURL=https://api.devguard.org, got: %s", result["INPUT_ARGS"])
		}
	})
}
