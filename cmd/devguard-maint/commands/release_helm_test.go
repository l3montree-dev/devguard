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

func TestUpdateHelmChartYAML(t *testing.T) {
	dir := t.TempDir()
	helmDir := filepath.Join(dir, "devguard-helm-chart")
	if err := os.MkdirAll(helmDir, 0o755); err != nil {
		t.Fatal(err)
	}

	chart := `apiVersion: v2
name: devguard
version: 1.0.0
appVersion: v1.0.0
`
	values := `image:
  repository: ghcr.io/l3montree-dev/devguard
  tag: v1.0.0
web:
  image:
    repository: ghcr.io/l3montree-dev/devguard-web
    tag: v1.0.0
exporter:
  image:
    repository: quay.io/prometheus/postgres-exporter
    tag: latest
ciComponentBase: "https://gitlab.com/l3montree/devguard/-/raw/v1.0.0/components"
`
	if err := os.WriteFile(filepath.Join(helmDir, "Chart.yaml"), []byte(chart), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helmDir, "values.yaml"), []byte(values), 0o644); err != nil {
		t.Fatal(err)
	}

	orig2, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig2) }()

	cl := &i.Changelog{}
	if err := updateHelmChart("v2.0.0", "2.0.0", "v2.0.1", "v2.0.3", cl); err != nil {
		t.Fatal(err)
	}

	gotChart, _ := os.ReadFile(filepath.Join(helmDir, "Chart.yaml"))
	if !strings.Contains(string(gotChart), "version: 2.0.0") {
		t.Errorf("Chart.yaml version not updated:\n%s", gotChart)
	}
	if !strings.Contains(string(gotChart), "appVersion: v2.0.0") {
		t.Errorf("Chart.yaml appVersion not updated:\n%s", gotChart)
	}

	gotValues, _ := os.ReadFile(filepath.Join(helmDir, "values.yaml"))
	content := string(gotValues)

	// api image should get apiTag
	if !strings.Contains(content, "tag: v2.0.1") {
		t.Errorf("api tag v2.0.1 missing in values.yaml:\n%s", content)
	}
	// web image should get webTag
	if !strings.Contains(content, "tag: v2.0.3") {
		t.Errorf("web tag v2.0.3 missing in values.yaml:\n%s", content)
	}
	// old tags must be gone
	if strings.Contains(content, "tag: v1.0.0") {
		t.Errorf("old tag v1.0.0 still present in values.yaml:\n%s", content)
	}
	// third-party image tag must be untouched
	if !strings.Contains(content, "tag: latest") {
		t.Errorf("third-party image tag was modified:\n%s", content)
	}
	if !strings.Contains(content, "/raw/v2.0.0/") {
		t.Errorf("ciComponentBase URL not updated:\n%s", content)
	}
}
