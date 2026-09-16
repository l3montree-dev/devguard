package services

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/openvex/go-vex/pkg/vex"
)

// sniffVexFormat detects the VEX document format from top-level JSON keys.
// nosemgrep: service-method-missing-ctx
func sniffVexFormat(body []byte) dtos.ExternalReferenceType {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		return dtos.ExternalReferenceTypeUnknown
	}
	if _, ok := probe["bomFormat"]; ok {
		return dtos.ExternalReferenceTypeCycloneDX
	}
	if _, ok := probe["document"]; ok {
		return dtos.ExternalReferenceTypeCSAF
	}
	if _, ok := probe["statements"]; ok {
		return dtos.ExternalReferenceTypeOpenVEX
	}
	if _, ok := probe["@context"]; ok {
		return dtos.ExternalReferenceTypeOpenVEX
	}
	return dtos.ExternalReferenceTypeUnknown
}

// vexRulesFromDocument decodes a CSAF or OpenVEX document and converts it into VEX rules.
// nosemgrep: service-method-missing-ctx
func VexRulesFromDocument(body []byte, source string) ([]models.UpstreamVEXRule, dtos.ExternalReferenceType, error) {
	format := sniffVexFormat(body)

	switch format {
	case dtos.ExternalReferenceTypeCSAF:
		var advisory gocsaf.Advisory
		if err := json.Unmarshal(body, &advisory); err != nil {
			return nil, format, fmt.Errorf("could not decode vex file as CSAF advisory: %w", err)
		}
		rules, err := transformer.CSAFVEXToRules(&advisory, source)
		return rules, format, err
	case dtos.ExternalReferenceTypeOpenVEX:
		var doc vex.VEX
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, format, fmt.Errorf("could not decode vex file as OpenVEX document: %w", err)
		}
		rules, err := transformer.OpenVEXToRules(&doc, source)
		return rules, format, err
	case dtos.ExternalReferenceTypeCycloneDX:
		var doc cyclonedx.BOM
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, format, fmt.Errorf("could not decode vex file as CycloneDX BOM: %w", err)
		}
		rules, err := transformer.CycloneDXVEXToRules(&doc, source)
		return rules, format, err
	default:
		return nil, format, fmt.Errorf("unsupported VEX document format")
	}
}

func downloadGithubRepoAsZip(ctx context.Context, baseURL, owner, repo, branch string) (*zip.Reader, error) {
	url := fmt.Sprintf(
		"%s/%s/%s/archive/refs/heads/%s.zip",
		baseURL,
		owner,
		repo,
		branch,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout:   10 * time.Minute,
		Transport: utils.EgressTransport,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return utils.ZipReaderFromResponse(resp)
	case http.StatusNotFound:
		return nil, fmt.Errorf("404 Source not found")
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("401 Unauthorized")
	case http.StatusInternalServerError:
		return nil, fmt.Errorf("500 Internal Server error")
	default:
		return nil, fmt.Errorf("Unexpected status: %d\n", resp.StatusCode)
	}
}

// only needed to avoid import cycles
type gitHubVexFetcher struct {
	// baseURL defaults to https://github.com; overridable in tests to point at an httptest.Server.
	baseURL string
}

func NewGitHubVexFetcher() gitHubVexFetcher {
	return gitHubVexFetcher{baseURL: "https://github.com"}
}

func (gh gitHubVexFetcher) FetchVexFromGitHub(ctx context.Context, targetURL string, targetBranch string) (vexRules []models.UpstreamVEXRule, err error) {
	owner, repo, err := parseGitHubURL(targetURL)
	if err != nil {
		return nil, err
	}

	// Determine default branch
	branch := targetBranch
	if branch == "" {
		branch = "main"
	}

	repoZip, err := downloadGithubRepoAsZip(ctx, gh.baseURL, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	allRules := make([]models.UpstreamVEXRule, 0, len(repoZip.File)*10) // rough estimate
	for _, fileEntry := range repoZip.File {
		if fileEntry.FileInfo().IsDir() {
			continue
		}
		filename := strings.ToLower(path.Base(fileEntry.Name))
		if !strings.HasSuffix(filename, ".json") {
			continue
		}

		fileRead, err := fileEntry.Open()
		if err != nil {
			slog.Info("document could not be opened, skipping this file for parsing", "filename", fileEntry.Name, "err", err)
			continue
		}

		bytes, err := io.ReadAll(fileRead)
		if err != nil {
			slog.Info("document could not be read, skipping this file for parsing", "filename", fileEntry.Name, "err", err)
			continue
		}
		rules, _, err := VexRulesFromDocument(
			bytes,
			targetURL,
		)
		if err != nil {
			slog.Info("could not create openVEX report structure", "err", err, "filename", filename)
			continue
		}
		allRules = append(allRules, rules...)
	}

	return utils.DeduplicateSlice(allRules, func(el models.UpstreamVEXRule) string {
		return el.ID
	}), nil
}

func parseGitHubURL(rawURL string) (owner string, repo string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	const githubDomain = "github.com"
	const gitSuffix = ".git"
	const trailingSlashSuffix = "/"
	if u.Host != githubDomain {
		return "", "", fmt.Errorf("invalid github repository url")
	}
	parts := strings.Split(strings.TrimSuffix(strings.Trim(u.Path, trailingSlashSuffix), gitSuffix), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid github repository url path: expected /{owner}/{repo}, got %q", u.Path)
	}
	owner = parts[0]
	repo = parts[1]
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("invalid github repository url path: expected non-empty owner and repo, got %q", u.Path)
	}
	return owner, repo, nil
}
