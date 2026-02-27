package commonint

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/gosimple/slug"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// devguardTemplate is the output of buildGitlabCiTemplate("full") with default env vars.
// Tests use it as the incoming template to merge into an existing .gitlab-ci.yml.
const devguardTemplate = `stages:
  - test
  - oci-image
  - attestation
include:
  - remote: "https://gitlab.com/l3montree/devguard/-/raw/main/templates/full.yml"
    inputs:
      devguard_asset_name: "$DEVGUARD_ASSET_NAME"
      devguard_token: "$DEVGUARD_TOKEN"
      devguard_api_url: "$DEVGUARD_API_URL"
      devguard_web_ui: "app.devguard.org"
`

func TestMergeGitlabCiTemplate(t *testing.T) {
	// Case 1: a simple Go project that has no include: block.
	// Expected: oci-image and attestation appended to stages (test already present),
	// include: block added at the end. Blank lines between jobs are not preserved
	// by the yaml.v3 encoder — this is the only formatting change.
	t.Run("simple Go project without existing include", func(t *testing.T) {
		existing := `# Build and test pipeline for the API service
stages:
  - build
  - test
  - deploy

variables:
  GO_VERSION: "1.22"
  BINARY_NAME: api-server

build:
  stage: build
  image: golang:${GO_VERSION}
  script:
    - go build -o $BINARY_NAME ./cmd/api

unit-test:
  stage: test
  image: golang:${GO_VERSION}
  script:
    - go test ./...

deploy-staging:
  stage: deploy
  script:
    - echo "Deploying to staging"
  environment:
    name: staging
  only:
    - main
`
		expected := `# Build and test pipeline for the API service
stages:
  - build
  - test
  - deploy
  - oci-image
  - attestation
variables:
  GO_VERSION: "1.22"
  BINARY_NAME: api-server
build:
  stage: build
  image: golang:${GO_VERSION}
  script:
    - go build -o $BINARY_NAME ./cmd/api
unit-test:
  stage: test
  image: golang:${GO_VERSION}
  script:
    - go test ./...
deploy-staging:
  stage: deploy
  script:
    - echo "Deploying to staging"
  environment:
    name: staging
  only:
    - main
include:
  - remote: "https://gitlab.com/l3montree/devguard/-/raw/main/templates/full.yml"
    inputs:
      devguard_asset_name: "$DEVGUARD_ASSET_NAME"
      devguard_token: "$DEVGUARD_TOKEN"
      devguard_api_url: "$DEVGUARD_API_URL"
      devguard_web_ui: "app.devguard.org"
`
		result, err := mergeGitlabCiTemplate([]byte(existing), devguardTemplate)
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})

	// Case 2: a Docker build project that already has an include: block (GitLab SAST template).
	// Expected: oci-image and attestation appended to stages (test already present),
	// devguard remote include appended after the existing template include.
	t.Run("Docker build project with existing GitLab template include", func(t *testing.T) {
		existing := `stages:
  - test
  - build
  - release

include:
  - template: "Security/SAST.gitlab-ci.yml"

variables:
  DOCKER_DRIVER: overlay2
  IMAGE_NAME: $CI_REGISTRY_IMAGE

lint:
  stage: test
  image: node:20
  script:
    - npm ci
    - npm run lint

docker-build:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker build -t $IMAGE_NAME:$CI_COMMIT_SHA .
    - docker push $IMAGE_NAME:$CI_COMMIT_SHA

release:
  stage: release
  script:
    - echo "Creating release"
  only:
    - tags
`
		expected := `stages:
  - test
  - build
  - release
  - oci-image
  - attestation
include:
  - template: "Security/SAST.gitlab-ci.yml"
  - remote: "https://gitlab.com/l3montree/devguard/-/raw/main/templates/full.yml"
    inputs:
      devguard_asset_name: "$DEVGUARD_ASSET_NAME"
      devguard_token: "$DEVGUARD_TOKEN"
      devguard_api_url: "$DEVGUARD_API_URL"
      devguard_web_ui: "app.devguard.org"
variables:
  DOCKER_DRIVER: overlay2
  IMAGE_NAME: $CI_REGISTRY_IMAGE
lint:
  stage: test
  image: node:20
  script:
    - npm ci
    - npm run lint
docker-build:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker build -t $IMAGE_NAME:$CI_COMMIT_SHA .
    - docker push $IMAGE_NAME:$CI_COMMIT_SHA
release:
  stage: release
  script:
    - echo "Creating release"
  only:
    - tags
`
		result, err := mergeGitlabCiTemplate([]byte(existing), devguardTemplate)
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})

	// Case 3: a complex microservices project with workflow rules, many stages, two
	// project-based includes, global default config, and multiple jobs with artifacts,
	// caches, and services. Expected: only oci-image and attestation are appended
	// (all other stages already present), devguard remote include appended as third entry.
	// The two-line header comment and the blank line below it are both preserved.
	t.Run("complex microservices project with workflow rules and project includes", func(t *testing.T) {
		existing := `# Production pipeline for the microservices platform
# Handles build, test, security scanning, and deployment

workflow:
  rules:
    - if: $CI_MERGE_REQUEST_ID
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

stages:
  - .pre
  - test
  - build
  - scan
  - package
  - deploy
  - .post

include:
  - project: "company/shared-ci-templates"
    ref: main
    file: "/templates/docker.yml"
  - project: "company/shared-ci-templates"
    ref: main
    file: "/templates/kubernetes.yml"

variables:
  KUBE_NAMESPACE: production
  DOCKER_BUILDKIT: "1"
  CACHE_KEY: ${CI_COMMIT_REF_SLUG}

default:
  tags:
    - kubernetes
  retry:
    max: 2
    when: runner_system_failure

unit-tests:
  stage: test
  image: golang:1.22
  cache:
    key: $CACHE_KEY
    paths:
      - vendor/
  script:
    - go test ./... -coverprofile=coverage.out
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.out

integration-tests:
  stage: test
  services:
    - name: postgres:15
      alias: db
  variables:
    POSTGRES_DB: testdb
    POSTGRES_PASSWORD: secret
  script:
    - go test ./integration/...

build-image:
  stage: build
  script:
    - docker build -t $IMAGE_TAG .

deploy-production:
  stage: deploy
  when: manual
  environment:
    name: production
    url: https://api.example.com
  script:
    - helm upgrade --install api ./chart
`
		expected := `# Production pipeline for the microservices platform
# Handles build, test, security scanning, and deployment

workflow:
  rules:
    - if: $CI_MERGE_REQUEST_ID
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
stages:
  - .pre
  - test
  - build
  - scan
  - package
  - deploy
  - .post
  - oci-image
  - attestation
include:
  - project: "company/shared-ci-templates"
    ref: main
    file: "/templates/docker.yml"
  - project: "company/shared-ci-templates"
    ref: main
    file: "/templates/kubernetes.yml"
  - remote: "https://gitlab.com/l3montree/devguard/-/raw/main/templates/full.yml"
    inputs:
      devguard_asset_name: "$DEVGUARD_ASSET_NAME"
      devguard_token: "$DEVGUARD_TOKEN"
      devguard_api_url: "$DEVGUARD_API_URL"
      devguard_web_ui: "app.devguard.org"
variables:
  KUBE_NAMESPACE: production
  DOCKER_BUILDKIT: "1"
  CACHE_KEY: ${CI_COMMIT_REF_SLUG}
default:
  tags:
    - kubernetes
  retry:
    max: 2
    when: runner_system_failure
unit-tests:
  stage: test
  image: golang:1.22
  cache:
    key: $CACHE_KEY
    paths:
      - vendor/
  script:
    - go test ./... -coverprofile=coverage.out
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.out
integration-tests:
  stage: test
  services:
    - name: postgres:15
      alias: db
  variables:
    POSTGRES_DB: testdb
    POSTGRES_PASSWORD: secret
  script:
    - go test ./integration/...
build-image:
  stage: build
  script:
    - docker build -t $IMAGE_TAG .
deploy-production:
  stage: deploy
  when: manual
  environment:
    name: production
    url: https://api.example.com
  script:
    - helm upgrade --install api ./chart
`
		result, err := mergeGitlabCiTemplate([]byte(existing), devguardTemplate)
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})
}

func TestRenderPathToComponent(t *testing.T) {
	t.Run("Everything works as expected with empty lists", func(t *testing.T) {
		components := []models.ComponentDependency{}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		pURL := "pkg:npm:test"

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, pURL)
		if err != nil {
			t.Fail()
		}
		// With empty components, the pURL is not reachable, so we get empty mermaid diagram
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\n\nclassDef default stroke-width:2px\n```\n", result)

	})
	t.Run("LoadPathToComponent fails somehow should return an error", func(t *testing.T) {
		components := []models.ComponentDependency{}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, fmt.Errorf("Something went wrong"))

		assetID := uuid.New()
		assetVersionName := "TestName"
		pURL := "pkg:npm:test"

		_, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, pURL)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("Everything works as expeted with a non empty component list", func(t *testing.T) {
		// Create a chain of actual components (all with pkg: prefix) to have a path with edges
		components := []models.ComponentDependency{
			{ComponentID: nil, DependencyID: "artifact:test-artifact", Dependency: models.Component{ID: "artifact:test-artifact"}},                                         // root --> artifact
			{ComponentID: utils.Ptr("artifact:test-artifact"), DependencyID: "sbom:test@test-artifact", Dependency: models.Component{ID: "sbom:test@test-artifact"}},       // artifact -> sbom
			{ComponentID: utils.Ptr("sbom:test@test-artifact"), DependencyID: "pkg:npm/root-dep@1.0.0", Dependency: models.Component{ID: "pkg:npm/root-dep@1.0.0"}},        // sbom -> root-dep (component)
			{ComponentID: utils.Ptr("pkg:npm/root-dep@1.0.0"), DependencyID: "pkg:npm/test-package@1.0.0", Dependency: models.Component{ID: "pkg:npm/test-package@1.0.0"}}, // root-dep -> test-package (component)
		}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		pURL := "pkg:npm/test-package@1.0.0" // Use a pURL that's actually in the component list

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, pURL)
		if err != nil {
			t.Fail()
		}

		// FindAllComponentOnlyPathsToPURL only returns component-only paths (nodes starting with pkg:)
		// The path should be: root-dep -> test-package
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\nYour_application([\"Your application\"]) --- pkg_npm_root_dep_1_0_0([\"pkg:npm/root-dep\\@1.0.0\"])\npkg_npm_root_dep_1_0_0([\"pkg:npm/root-dep\\@1.0.0\"]) --- pkg_npm_test_package_1_0_0([\"pkg:npm/test-package\\@1.0.0\"])\n\nclassDef default stroke-width:2px\n```\n", result)

	})
	t.Run("should escape @ symbols", func(t *testing.T) {
		// Create a chain of actual components to verify @ escaping in mermaid output
		components := []models.ComponentDependency{
			{ComponentID: nil, DependencyID: "artifact:test-artifact", Dependency: models.Component{ID: "artifact:test-artifact"}},                                         // root --> artifact
			{ComponentID: utils.Ptr("artifact:test-artifact"), DependencyID: "sbom:test@test-artifact", Dependency: models.Component{ID: "sbom:test@test-artifact"}},       // artifact -> sbom
			{ComponentID: utils.Ptr("sbom:test@test-artifact"), DependencyID: "pkg:npm/root-dep@1.0.0", Dependency: models.Component{ID: "pkg:npm/root-dep@1.0.0"}},        // sbom -> root-dep (component)
			{ComponentID: utils.Ptr("pkg:npm/root-dep@1.0.0"), DependencyID: "pkg:npm/test-package@1.0.0", Dependency: models.Component{ID: "pkg:npm/test-package@1.0.0"}}, // root-dep -> test-package (component)
		}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"

		pURL := "pkg:npm/test-package@1.0.0" // Use a pURL that's actually in the component list

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, pURL)
		if err != nil {
			t.Fail()
		}

		// Verify @ symbols are escaped as \@ in the mermaid output
		assert.Contains(t, result, "\\@1.0.0")
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\nYour_application([\"Your application\"]) --- pkg_npm_root_dep_1_0_0([\"pkg:npm/root-dep\\@1.0.0\"])\npkg_npm_root_dep_1_0_0([\"pkg:npm/root-dep\\@1.0.0\"]) --- pkg_npm_test_package_1_0_0([\"pkg:npm/test-package\\@1.0.0\"])\n\nclassDef default stroke-width:2px\n```\n", result)

	})

	t.Run("should render single node path", func(t *testing.T) {
		// Simulate a single node path (e.g., only root component)
		components := []models.ComponentDependency{
			{ComponentID: nil, DependencyID: "pkg:npm/single@1.0.0", Dependency: models.Component{ID: "pkg:npm/single@1.0.0"}},
		}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		pURL := "pkg:npm/single@1.0.0"

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, pURL)
		assert.NoError(t, err)
		// The output should contain the single node mermaid representation
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\nYour_application([\"Your application\"]) --- pkg_npm_single_1_0_0([\"pkg:npm/single\\@1.0.0\"])\n\nclassDef default stroke-width:2px\n```\n", result)
	})
}
func TestGetLabels(t *testing.T) {
	t.Run("should return correct labels for a DependencyVuln with CVE", func(t *testing.T) {
		vuln := &models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State: dtos.VulnStateOpen,
			},
			Artifacts: []models.Artifact{
				{ArtifactName: "source-code"},
				{ArtifactName: "container"},
				{ArtifactName: "container:test"},
				{ArtifactName: "source-code:test"},
			},
			RawRiskAssessment: utils.Ptr(0.2),
		}
		expectedLabels := []string{
			"devguard",
			"state:open",
			"risk:low",
			"container",
			"container:test",
			"source-code",
			"source-code:test",
		}

		assert.Equal(t, expectedLabels, GetLabels(vuln))
	})

	t.Run("should return correct labels for a FirstPartyVuln", func(t *testing.T) {
		vuln := &models.FirstPartyVuln{
			Vulnerability: models.Vulnerability{
				State: dtos.VulnStateFixed,
			},
			ScannerIDs: "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sast github.com/l3montree-dev/devguard/cmd/devguard-scanner/secret-scanning github.com/l3montree-dev/devguard/cmd/devguard-scanner/iac",
		}

		expectedLabels := []string{
			"devguard",
			"state:fixed",
			"sast",
			"secret-scanning",
			"iac",
		}

		assert.Equal(t, expectedLabels, GetLabels(vuln))
	})

}

func TestBuildGitlabCiTemplate(t *testing.T) {

	t.Run("should build full template with default environment variables", func(t *testing.T) {
		// Clear environment variables to test defaults
		os.Unsetenv("DEVGUARD_CI_COMPONENT_BASE")
		os.Unsetenv("FRONTEND_URL")

		result, err := buildGitlabCiTemplate("full")

		assert.NoError(t, err)
		assert.Contains(t, result, "stages:")
		assert.Contains(t, result, "- test")
		assert.Contains(t, result, "- oci-image")
		assert.Contains(t, result, "- attestation")
		assert.Contains(t, result, "include:")
		assert.Contains(t, result, "remote: \"https://gitlab.com/l3montree/devguard/-/raw/main/templates/full.yml\"")
		assert.Contains(t, result, "web_ui: \"app.devguard.org\"")
		assert.Contains(t, result, "asset_name: \"$DEVGUARD_ASSET_NAME\"")
		assert.Contains(t, result, "token: \"$DEVGUARD_TOKEN\"")
		assert.Contains(t, result, "api_url: \"$DEVGUARD_API_URL\"")
	})

	t.Run("should build full template with custom environment variables", func(t *testing.T) {
		// Set custom environment variables
		os.Setenv("DEVGUARD_CI_COMPONENT_BASE", "https://custom.gitlab.com/devguard/-/raw/main")
		os.Setenv("FRONTEND_URL", "custom.devguard.example.com")
		defer func() {
			os.Unsetenv("DEVGUARD_CI_COMPONENT_BASE")
			os.Unsetenv("FRONTEND_URL")
		}()

		result, err := buildGitlabCiTemplate("full")

		assert.NoError(t, err)
		assert.Contains(t, result, "remote: \"https://custom.gitlab.com/devguard/-/raw/main/templates/full.yml\"")
		assert.Contains(t, result, "web_ui: \"custom.devguard.example.com\"")
	})

	t.Run("should handle empty environment variables and use defaults", func(t *testing.T) {
		// Set empty environment variables
		os.Setenv("DEVGUARD_CI_COMPONENT_BASE", "")
		os.Setenv("FRONTEND_URL", "")
		defer func() {
			os.Unsetenv("DEVGUARD_CI_COMPONENT_BASE")
			os.Unsetenv("FRONTEND_URL")
		}()

		result, err := buildGitlabCiTemplate("full")

		assert.NoError(t, err)
		assert.Contains(t, result, "remote: \"https://gitlab.com/l3montree/devguard/-/raw/main/templates/full.yml\"")
		assert.Contains(t, result, "web_ui: \"app.devguard.org\"")
	})

	t.Run("should NOT return error for unknown template ID", func(t *testing.T) {
		result, err := buildGitlabCiTemplate("unknown")

		assert.Nil(t, err)

		// defaults to full
		assert.Contains(t, result, "stages:")
		assert.Contains(t, result, "- test")
		assert.Contains(t, result, "- oci-image")
		assert.Contains(t, result, "- attestation")
		assert.Contains(t, result, "include:")
		assert.Contains(t, result, "remote: \"https://gitlab.com/l3montree/devguard/-/raw/main/templates/full.yml\"")
		assert.Contains(t, result, "web_ui: \"app.devguard.org\"")
	})

	t.Run("should generate valid YAML structure", func(t *testing.T) {
		result, err := buildGitlabCiTemplate("full")

		assert.NoError(t, err)
		// Verify basic YAML structure
		lines := strings.Split(result, "\n")
		assert.True(t, len(lines) > 0)

		// Check that stages section exists and is properly formatted
		hasStages := false
		hasInclude := false
		for _, line := range lines {
			if strings.TrimSpace(line) == "stages:" {
				hasStages = true
			}
			if strings.TrimSpace(line) == "include:" {
				hasInclude = true
			}
		}
		assert.True(t, hasStages, "Template should contain stages section")
		assert.True(t, hasInclude, "Template should contain include section")
	})
}

func TestRenderMarkdown(t *testing.T) {

	baseURL := "https://devguard.example.com"
	orgSlug := "my-org"
	projectSlug := "my-project"
	assetSlug := "my-asset"
	assetVersionName := "v1.0.0"

	assertVersionSlug := slug.Make(assetVersionName)
	assert.Equal(t, "v1-0-0", assertVersionSlug)

	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		snippetContents := dtos.SnippetContents{
			Snippets: []dtos.SnippetContent{
				{
					StartLine:   64,
					EndLine:     64,
					StartColumn: 1,
					EndColumn:   20,
					Snippet:     "TestSnippet",
				},
			},
		}
		snippetJSON, err := transformer.SnippetContentsToJSON(snippetContents)
		assert.NoError(t, err)

		firstPartyVuln := models.FirstPartyVuln{
			SnippetContents: snippetJSON,
			Vulnerability: models.Vulnerability{Message: utils.Ptr("A detailed Message"),
				ID: "test-vuln-id",
			},
			URI: "the/uri/of/the/vuln",
		}
		result := RenderMarkdownForFirstPartyVuln(firstPartyVuln, baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug)
		assert.Contains(t, result, "A detailed Message")
		assert.Contains(t, result, "TestSnippet")
		assert.Contains(t, result, "**Found at:** [the/uri/of/the/vuln](../the/uri/of/the/vuln#L64)")
		assert.Contains(t, result, fmt.Sprintf("More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/code-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug, firstPartyVuln.ID))
	})
	t.Run("vuln without snippet contents", func(t *testing.T) {
		snippetContents := dtos.SnippetContents{
			Snippets: []dtos.SnippetContent{
				{},
			},
		}
		snippetJSON, err := transformer.SnippetContentsToJSON(snippetContents)
		assert.NoError(t, err)
		firstPartyVuln := models.FirstPartyVuln{
			SnippetContents: snippetJSON,
			Vulnerability: models.Vulnerability{Message: utils.Ptr("A detailed Message"),
				ID: "test-vuln-id"},
			URI: "the/uri/of/the/vuln",
		}

		result := RenderMarkdownForFirstPartyVuln(firstPartyVuln, baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug)
		assert.Contains(t, result, "A detailed Message")
		assert.Contains(t, result, "**Found at:** [the/uri/of/the/vuln](../the/uri/of/the/vuln#L0)")
		assert.Contains(t, result, fmt.Sprintf("More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/code-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug, firstPartyVuln.ID))
	})
}

// TestTicketContentBitwiseReproducibility proves that GitLab ticket content
// (labels and Mermaid path diagrams) is identical byte-for-byte across runs,
// regardless of the order in which artifacts or components are provided.
func TestTicketContentBitwiseReproducibility(t *testing.T) {
	t.Run("GetLabels produces identical output regardless of artifact slice order", func(t *testing.T) {
		artifacts := []models.Artifact{
			{ArtifactName: "source-code"},
			{ArtifactName: "container"},
			{ArtifactName: "binary"},
		}

		// Three permutations of the same artifact set
		orders := [][]models.Artifact{
			{artifacts[0], artifacts[1], artifacts[2]},
			{artifacts[2], artifacts[0], artifacts[1]},
			{artifacts[1], artifacts[2], artifacts[0]},
		}

		var reference []string
		for i, order := range orders {
			vuln := &models.DependencyVuln{
				Vulnerability:     models.Vulnerability{State: dtos.VulnStateOpen},
				Artifacts:         order,
				RawRiskAssessment: utils.Ptr(0.5),
			}
			labels := GetLabels(vuln)
			if i == 0 {
				reference = labels
			} else {
				assert.Equal(t, reference, labels, "labels differ for artifact permutation %d", i)
			}
		}
	})

	t.Run("RenderPathToComponent produces identical Mermaid output across repeated calls", func(t *testing.T) {
		// Graph: sbom → route-b and route-a (intentionally "wrong" alphabetical order in slice)
		// both routes lead to the target, producing two component-only paths.
		// Previously, map iteration randomness caused the two path edges to appear
		// in non-deterministic order in the Mermaid output.
		components := []models.ComponentDependency{
			{ComponentID: nil, DependencyID: "artifact:art", Dependency: models.Component{ID: "artifact:art"}},
			{ComponentID: utils.Ptr("artifact:art"), DependencyID: "sbom:s@art", Dependency: models.Component{ID: "sbom:s@art"}},
			{ComponentID: utils.Ptr("sbom:s@art"), DependencyID: "pkg:npm/route-b@1.0", Dependency: models.Component{ID: "pkg:npm/route-b@1.0"}},
			{ComponentID: utils.Ptr("sbom:s@art"), DependencyID: "pkg:npm/route-a@1.0", Dependency: models.Component{ID: "pkg:npm/route-a@1.0"}},
			{ComponentID: utils.Ptr("pkg:npm/route-a@1.0"), DependencyID: "pkg:npm/target@1.0", Dependency: models.Component{ID: "pkg:npm/target@1.0"}},
			{ComponentID: utils.Ptr("pkg:npm/route-b@1.0"), DependencyID: "pkg:npm/target@1.0", Dependency: models.Component{ID: "pkg:npm/target@1.0"}},
		}

		assetID := uuid.New()
		pURL := "pkg:npm/target@1.0"

		// Run 50 times — enough to surface any map-iteration randomness.
		const runs = 50
		results := make([]string, runs)
		for i := range runs {
			repo := mocks.NewComponentRepository(t)
			repo.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)
			result, err := RenderPathToComponent(repo, assetID, "v1.0.0", pURL)
			assert.NoError(t, err)
			results[i] = result
		}

		for i := 1; i < runs; i++ {
			assert.Equal(t, results[0], results[i], "Mermaid output differed on run %d", i)
		}

		// Also verify route-a edges appear before route-b edges (alphabetical DFS order).
		assert.Less(t,
			strings.Index(results[0], "route-a"),
			strings.Index(results[0], "route-b"),
			"route-a should appear before route-b in sorted DFS output",
		)
	})
}
