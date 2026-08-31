package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	i "github.com/l3montree-dev/devguard/cmd/devguard-maint/internal"
)

func TestUpdateDockerDeployment(t *testing.T) {
	dir := t.TempDir()
	deploymentDir := filepath.Join(dir, "devguard-docker-deployment")
	if err := os.MkdirAll(deploymentDir, 0o755); err != nil {
		t.Fatal(err)
	}

	env := `DEVGUARD_API_TAG=v1.0.0
DEVGUARD_WEB_TAG=v1.0.0
POSTGRESQL_TAG=v1.0.0
KRATOS_TAG=v1.0.0
TRAEFIK_TAG=v3.7
`
	envFile := filepath.Join(deploymentDir, ".env.example")
	if err := os.WriteFile(envFile, []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}

	// updateDockerDeployment uses relative paths — run from temp dir
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	cl := &i.Changelog{}
	if _, err := updateDockerDeployment("v2.0.1", "v2.0.3", cl); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(envFile)
	content := string(got)

	for _, want := range []string{
		"DEVGUARD_API_TAG=v2.0.1",
		"POSTGRESQL_TAG=v2.0.1",
		"KRATOS_TAG=v2.0.1",
		"DEVGUARD_WEB_TAG=v2.0.3",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("missing %q in output:\n%s", want, content)
		}
	}
	// unrelated tag variable must be untouched
	if !strings.Contains(content, "TRAEFIK_TAG=v3.7") {
		t.Error("unrelated tag variable was modified")
	}
	if cl.HasErrors() {
		t.Error("unexpected errors in changelog")
	}
}
