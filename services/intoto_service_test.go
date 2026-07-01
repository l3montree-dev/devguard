package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
)

func TestCreateDirWithLinkFilesNoPathTraversal(t *testing.T) {
	links := []models.InTotoLink{
		{
			Filename:      "../../../../../../../../tmp/devguard_pwned",
			Payload:       "<validly-signed-payload>",
			SupplyChainID: "test-supply-chain-id",
			Step:          "build",
		},
	}

	dir, err := createDirWithLinkFiles(links)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("Expected no error reading dir, got %v", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(filepath.Clean(name), "..") || filepath.IsAbs(name) {
			t.Errorf("file %q escapes the temp directory — path traversal vulnerability", name)
		}
	}

	// the malicious traversal must not have created a file outside the temp dir
	if _, err := os.Stat("/tmp/devguard_pwned"); err == nil {
		t.Error("file was written outside the temp directory — path traversal successful")
	}
}
