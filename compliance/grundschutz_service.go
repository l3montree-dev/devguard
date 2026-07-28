package compliance

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"golang.org/x/sync/singleflight"
)

const csvFetchTimeout = 5 * time.Second

//go:embed oscal/catalogs/Grundschutz++-catalog.json
var grundschutzCatalogJSON []byte

func grundschutzAdditionalMapper(groupTitle *string, controlProps *[]oscalTypes.Property, parts []oscalTypes.Part) map[string]any {
	additional := make(map[string]any)
	if groupTitle != nil {
		additional["group_title"] = *groupTitle
	}
	for _, prop := range derefProps(controlProps) {
		switch prop.Name {
		case "sec_level":
			additional["security_level"] = enrichProp(prop)
		case "effort_level":
			additional["effort_level"] = enrichProp(prop)
		case "tags":
			additional["tags"] = enrichProp(prop)
		}

	}
	for _, p := range parts {
		if p.Name == "guidance" && p.Prose != "" {
			additional["guidance"] = p.Prose
		}
		if p.Name == "statement" {
			for _, prop := range derefProps(p.Props) {
				switch prop.Name {
				case "modal_verb":
					additional["importance"] = enrichProp(prop)
				case "action_word":
					additional["word_definition"] = enrichProp(prop)
				case "result":
					additional["result"] = enrichProp(prop)
				case "result_specification":
					additional["result_specification"] = enrichProp(prop)
				case "documentation":
					additional["documentation"] = enrichProp(prop)
				}
			}
		}

	}
	return additional
}

func loadGrundschutzControls() ([]models.FrameworkControl, error) {
	catalog, err := parseOSCALCatalog(bytes.NewReader(grundschutzCatalogJSON))
	if err != nil {
		return nil, err
	}
	return extractControlsFromCatalog(catalog, "Grundschutz++", grundschutzAdditionalMapper), nil
}

type newProperty struct {
	oscalTypes.Property
	Definitions map[string]string `json:"definitions"`
}

type csvCacheEntry struct {
	records [][]string
	err     error
}

var (
	csvCacheMu sync.Mutex
	csvCache   = make(map[string]csvCacheEntry)
	csvGroup   singleflight.Group
)

// fetchCSVRecords fetches and parses the CSV at rawURL, caching both the
// result AND any error so the same URL is only ever fetched once per
// process - a URL that 404s would otherwise be re-fetched over the network
// on every single occurrence across the catalog (there can be thousands).
// Concurrent callers for the same not-yet-cached URL are coalesced into a
// single in-flight request via singleflight.
func fetchCSVRecords(rawURL string) ([][]string, error) {
	csvCacheMu.Lock()
	if entry, ok := csvCache[rawURL]; ok {
		csvCacheMu.Unlock()
		return entry.records, entry.err
	}
	csvCacheMu.Unlock()

	result, _, _ := csvGroup.Do(rawURL, func() (any, error) {
		records, err := doFetchCSVRecords(rawURL)
		entry := csvCacheEntry{records: records, err: err}

		csvCacheMu.Lock()
		csvCache[rawURL] = entry
		csvCacheMu.Unlock()

		return entry, nil
	})
	entry := result.(csvCacheEntry)
	return entry.records, entry.err
}

func doFetchCSVRecords(rawURL string) ([][]string, error) {
	reqCtx, cancel := context.WithTimeout(context.Background(), csvFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := utils.EgressClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d for %s", resp.StatusCode, rawURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(bytes.NewReader(body))
	return reader.ReadAll()
}

func enrichProp(prop oscalTypes.Property) any {
	var newProp newProperty
	newProp.Property = prop
	newProp.Definitions = make(map[string]string)

	words := strings.Split(newProp.Value, ",")
	if newProp.Ns == "" || len(words) == 0 {
		return newProp
	}

	rawURL := toRawGithubURL(newProp.Ns)

	records, err := fetchCSVRecords(rawURL)
	if err != nil {
		return newProp
	}
	if len(records) == 0 || len(records[0]) < 2 {
		return newProp
	}

	definitionCol := 1
	for i, header := range records[0] {
		if strings.EqualFold(strings.TrimSpace(header), "Definition") {
			definitionCol = i
			break
		}
	}

	for _, record := range records[1:] {
		if len(record) <= definitionCol {
			continue
		}
		for _, word := range words {
			if strings.EqualFold(strings.TrimSpace(record[0]), strings.TrimSpace(word)) {
				newProp.Definitions[word] = record[definitionCol]
			}
		}
	}

	return newProp
}

// toRawGithubURL converts a github.com "blob" URL into its raw.githubusercontent.com equivalent.
func toRawGithubURL(url string) string {
	if strings.Contains(url, "raw.githubusercontent.com") {
		return url
	}
	rawURL := strings.Replace(url, "github.com", "raw.githubusercontent.com", 1)
	rawURL = strings.Replace(rawURL, "/tree/", "/refs/heads/", 1)
	return rawURL
}
