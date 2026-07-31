package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
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
func VexRulesFromDocument(body []byte, assetID uuid.UUID, source string) ([]models.SystemVEXRule, dtos.ExternalReferenceType, error) {
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

func FetchSbomsFromUpstream(ctx context.Context, artifactName string, ref string, upstreamURLs []string) (boms []*normalize.SBOMGraph, validURLs []string, invalidURLs []dtos.ExternalReferenceError) {

	//check if the upstream urls are valid urls
	for _, url := range upstreamURLs {
		url = normalize.SanitizeExternalReferencesURL(url)
		// skip CSAF URLs - they're handled separately
		if strings.HasSuffix(url, "/provider-metadata.json") {
			continue
		}
		//check if the file is a valid url
		if url == "" || !strings.HasPrefix(url, "http") {
			invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
				URL:    url,
				Reason: "invalid url, no http prefix found",
			})
			continue
		}

		var bom cyclonedx.BOM
		ctx, cancel := context.WithTimeout(ctx, time.Second*30)
		defer cancel()
		// fetch the file from the url
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)

		if err != nil {
			invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
				URL:    url,
				Reason: fmt.Sprintf("could not create request for url: %v", err),
			})
			continue
		}

		resp, err := utils.EgressClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
				URL:    url,
				Reason: fmt.Sprintf("could not fetch url or non 200 status code: %v", err),
			})
			continue
		}
		defer resp.Body.Close()

		// download the url and check if it is a valid sbom
		file, err := io.ReadAll(resp.Body)
		if err != nil {
			invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
				URL:    url,
				Reason: fmt.Sprintf("could not read response body: %v", err),
			})
			continue
		}

		err = json.Unmarshal(file, &bom)
		if err != nil {
			invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
				URL:    url,
				Reason: fmt.Sprintf("could not unmarshal response body into cyclonedx bom: %v", err),
			})
			continue
		}

		// Only process SBOMs (not VEX)
		if normalize.BomIsSBOM(&bom) {
			normalizedBOM, err := normalize.SBOMGraphFromCycloneDX(&bom, artifactName, url)
			if err != nil {
				slog.Warn("could not normalize sbom from url", "err", err, "url", url)
				invalidURLs = append(invalidURLs, dtos.ExternalReferenceError{
					URL:    url,
					Reason: fmt.Sprintf("could not normalize sbom: %v", err),
				})
				continue
			}

			validURLs = append(validURLs, url)
			// add the sbom prefix
			boms = append(boms, normalizedBOM)
		}
	}

	return boms, validURLs, invalidURLs
}

// FetchVexFromUpstream downloads VEX from the given external references and converts it into
// VEX rules scoped to the given asset version. CSAF, OpenVEX and CycloneDX are parsed to rules by
// their respective transformers; the returned rules carry their VexSource (the reference URL).
func FetchVexFromUpstream(ctx context.Context, assetID uuid.UUID, string, upstreamURLs []string) ([]models.VEXRule, []models.ExternalReference, []models.ExternalReference) {
	rules := make([]models.VEXRule, 0)
	valid := make([]models.ExternalReference, 0, len(upstreamURLs))
	invalid := make([]models.ExternalReference, 0, len(upstreamURLs))
	mut := sync.Mutex{}
	wg := sync.WaitGroup{}
	for _, url := range upstreamURLs {
		// fetch the url and sniff the type
		wg.Go(func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				mut.Lock()
				invalid = append(invalid, models.ExternalReference{
					AssetID: assetID,
					URL:     url,
					Type:    dtos.ExternalReferenceTypeUnknown,
					Error:   new(fmt.Sprintf("could not create request for url: %v", err)),
				})
				return
			}

			resp, err := utils.EgressClient.Do(req)
			if err != nil {
				mut.Lock()
				invalid = append(invalid, models.ExternalReference{})
				return
			}

			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				mut.Lock()
				invalid = append(invalid, models.ExternalReference{
					AssetID: assetID,
					URL:     url,
					Type:    dtos.ExternalReferenceTypeUnknown,
					Error:   new(fmt.Sprintf("could not read response body: %v", err)),
				})
				return
			}
			vexRules, format, err := VexRulesFromDocument(body, assetID, url)
			if err != nil {
				mut.Lock()
				invalid = append(invalid, models.ExternalReference{
					Type:    format,
					Error:   new(fmt.Sprintf("could not parse vex file from url: %v", err)),
					AssetID: assetID,
					URL:     url,
				})
				return
			}
			for i := range vexRules {
				rules = append(rules, transformer.SystemVEXRuleToVEXRule(vexRules[i], "", assetID))
			}
			mut.Lock()
			valid = append(valid, models.ExternalReference{
				URL:     url,
				AssetID: assetID,
				Type:    format,
			})
			mut.Unlock()
		})
	}
	wg.Wait()
	return rules, valid, invalid
}

func FetchVexFromGitHub(ctx context.Context, targetURL string, targetBranch string) (vexRules []models.SystemVEXRule, err error) {
	owner, repo, err := ParseGitHubURL(targetURL)
	if err != nil {
		return nil, err
	}

	// Determine default branch
	branch := targetBranch
	if branch == "" {
		branch = "main"
	}

	resp, err := downloadRawFileFn(ctx, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	repoZip, err := utils.ZipReaderFromResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("could not read obtained zip: %w", err)
	}
	resp.Body.Close()

	allRules := make([]models.SystemVEXRule, 0, len(repoZip.File)*10) // rough estimate
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
			uuid.Nil,
			fileEntry.Name,
		)
		if err != nil {
			slog.Info("could not create openVEX report structure", "err", err, "filename", filename)
			continue
		}
		allRules = append(allRules, rules...)
	}
	return allRules, nil
}

func ParseGitHubURL(rawURL string) (owner string, repo string, err error) {
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

func DownloadGithubRepoAsZip(ctx context.Context, owner, repo, branch string) (*http.Response, error) {
	url := fmt.Sprintf(
		"https://github.com/%s/%s/archive/refs/heads/%s.zip",
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
		return resp, nil
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
