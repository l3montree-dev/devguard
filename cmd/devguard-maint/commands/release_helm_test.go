package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	i "github.com/l3montree-dev/devguard/cmd/devguard-maint/internal"
)

func TestUpdateDockerCompose(t *testing.T) {
	dir := t.TempDir()
	devguardDir := filepath.Join(dir, "devguard")
	if err := os.MkdirAll(devguardDir, 0o755); err != nil {
		t.Fatal(err)
	}

	compose := `services:
  api:
    image: ghcr.io/l3montree-dev/devguard:v1.0.0
  web:
    image: ghcr.io/l3montree-dev/devguard-web:v1.0.0
  db:
    image: ghcr.io/l3montree-dev/devguard/postgresql:v1.0.0
  exporter:
    image: some-other-image:latest
`
	composeFile := filepath.Join(devguardDir, "docker-compose-try-it.yaml")
	if err := os.WriteFile(composeFile, []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}

	// updateDockerCompose uses relative paths — run from temp dir
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	cl := &i.Changelog{}
	if err := updateDockerCompose("v2.0.1", "v2.0.3", cl); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(composeFile)
	content := string(got)

	for _, want := range []string{
		"ghcr.io/l3montree-dev/devguard:v2.0.1",
		"ghcr.io/l3montree-dev/devguard/postgresql:v2.0.1",
		"ghcr.io/l3montree-dev/devguard-web:v2.0.3",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("missing %q in output:\n%s", want, content)
		}
	}
	// third-party image must be untouched
	if !strings.Contains(content, "some-other-image:latest") {
		t.Error("third-party image was modified")
	}
	if cl.HasErrors() {
		t.Error("unexpected errors in changelog")
	}
}

