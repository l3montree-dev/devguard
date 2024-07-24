package vulndb

import "testing"

func TestTransformVersionToCPE(t *testing.T) {
	t.Run("empty version", func(t *testing.T) {
		version := ""
		_, err := transformVersionToRange(version)

		if err == nil {
			t.Errorf("Expected error")
		}
	})

	t.Run("= 2.45.0", func(t *testing.T) {
		version := "= 2.45.0"
		expected := "2.45.0"
		result, err := transformVersionToRange(version)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if *result.concreteVersion != expected {
			t.Errorf("Expected %s, got %s", expected, *result.concreteVersion)
		}
	})

	t.Run(">= 2.19.0, 2.19.5", func(t *testing.T) {
		version := ">= 2.19.0, 2.19.5"
		result, err := transformVersionToRange(version)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if *result.versionStartIncluding != "2.19.0" {
			t.Errorf("Expected %s, got %s", "2.19.0", *result.versionStartIncluding)
		}

		if *result.versionEndIncluding != "2.19.5" {
			t.Errorf("Expected %s, got %s", "2.19.5", *result.versionEndIncluding)
		}
	})
}
