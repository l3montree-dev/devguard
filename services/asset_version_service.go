package services

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
)

type assetVersionService struct {
	componentRepository    shared.ComponentRepository
	assetVersionRepository shared.AssetVersionRepository
	componentService       shared.ComponentService
	thirdPartyIntegration  shared.IntegrationAggregate
	licenseRiskRepository  shared.LicenseRiskRepository
	utils.FireAndForgetSynchronizer
}

var _ shared.AssetVersionService = &assetVersionService{}

func NewAssetVersionService(assetVersionRepository shared.AssetVersionRepository, componentRepository shared.ComponentRepository, componentService shared.ComponentService, thirdPartyIntegration shared.IntegrationAggregate, licenseRiskRepository shared.LicenseRiskRepository, synchronizer utils.FireAndForgetSynchronizer) *assetVersionService {
	return &assetVersionService{
		assetVersionRepository:    assetVersionRepository,
		componentRepository:       componentRepository,
		componentService:          componentService,
		thirdPartyIntegration:     thirdPartyIntegration,
		licenseRiskRepository:     licenseRiskRepository,
		FireAndForgetSynchronizer: synchronizer,
	}
}

func (s *assetVersionService) GetAssetVersionsByAssetID(assetID uuid.UUID) ([]models.AssetVersion, error) {
	return s.assetVersionRepository.GetAssetVersionsByAssetID(nil, assetID)
}

var sarifResultKindsIndicatingNotAndIssue = []string{
	"notApplicable",
	"informational",
	"pass",
	"open",
}

func getBestDescription(rule sarif.ReportingDescriptor) string {
	if rule.FullDescription != nil {
		if rule.FullDescription.Markdown != nil {
			return utils.OrDefault(rule.FullDescription.Markdown, "")
		}
		if rule.FullDescription.Text != "" {
			return rule.FullDescription.Text
		}
	}
	if rule.ShortDescription.Markdown != nil {
		return utils.OrDefault(rule.ShortDescription.Markdown, "")
	}

	return rule.ShortDescription.Text
}

func preferMarkdown(text sarif.MultiformatMessageString) string {
	if text.Markdown != nil {
		return utils.OrDefault(text.Markdown, "")
	}
	return text.Text
}

func (s *assetVersionService) UpdateSBOM(tx shared.DB, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifactName string, sbom *normalize.SBOMGraph, upstream dtos.UpstreamState) (*normalize.SBOMGraph, error) {
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		return nil, fmt.Errorf("FRONTEND_URL environment variable is not set")
	}

	// Load the full SBOM graph from the database
	wholeAssetGraph, err := s.LoadFullSBOMGraph(assetVersion)
	if err != nil {
		return nil, errors.Wrap(err, "could not build whole asset sbom graph")
	}

	diff := wholeAssetGraph.MergeGraph(sbom)

	if err := s.componentRepository.HandleStateDiff(tx, assetVersion, wholeAssetGraph, diff); err != nil {
		return nil, errors.Wrap(err, "could not handle state diff")
	}

	// update the license information in the background
	s.FireAndForget(func() {
		slog.Info("updating license information in background", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
		_, err := s.componentService.GetAndSaveLicenseInformation(assetVersion, utils.Ptr(artifactName), false, upstream)
		if err != nil {
			slog.Error("could not update license information", "asset", assetVersion.Name, "assetID", assetVersion.AssetID, "err", err)
		} else {
			slog.Info("license information updated", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
		}
	})

	if assetVersion.DefaultBranch || assetVersion.Type == models.AssetVersionTag {
		s.FireAndForget(func() {
			// Export the updated graph back to CycloneDX format for the event
			exportedBOM := wholeAssetGraph.ToCycloneDX(normalize.BOMMetadata{
				RootName: artifactName,
			})
			if err = s.thirdPartyIntegration.HandleEvent(shared.SBOMCreatedEvent{
				AssetVersion: shared.ToAssetVersionObject(assetVersion),
				Asset:        shared.ToAssetObject(asset),
				Project:      shared.ToProjectObject(project),
				Org:          shared.ToOrgObject(org),
				Artifact: shared.ArtifactObject{
					ArtifactName: artifactName,
				},
				SBOM: exportedBOM,
			}); err != nil {
				slog.Error("could not handle SBOM updated event", "err", err)
			} else {
				slog.Info("handled SBOM updated event", "assetVersion", assetVersion.Name, "assetID", assetVersion.AssetID)
			}
		})
	}

	return wholeAssetGraph, nil
}

// LoadFullSBOMGraph loads all components for an asset version and builds a complete SBOMGraph.
// This is the new graph-based approach that will eventually replace LoadFullSBOM.
func (s *assetVersionService) LoadFullSBOMGraph(assetVersion models.AssetVersion) (*normalize.SBOMGraph, error) {
	licenseRisks, err := s.licenseRiskRepository.GetAllOverwrittenLicensesForAssetVersion(assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return nil, err
	}
	componentLicenseOverwrites := make(map[string]string, len(licenseRisks))
	for i := range licenseRisks {
		if licenseRisks[i].FinalLicenseDecision != nil {
			componentLicenseOverwrites[licenseRisks[i].ComponentPurl] = *licenseRisks[i].FinalLicenseDecision
		}
	}

	// Load ALL components for the asset version
	components, err := s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not load components")
	}

	return normalize.SBOMGraphFromComponents(utils.MapType[normalize.GraphComponent](components), componentLicenseOverwrites), nil
}

func dependencyVulnToOpenVexStatus(dependencyVuln models.DependencyVuln) vex.Status {
	switch dependencyVuln.State {
	case dtos.VulnStateOpen:
		return vex.StatusUnderInvestigation
	case dtos.VulnStateFixed:
		return vex.StatusFixed
	case dtos.VulnStateFalsePositive:
		return vex.StatusNotAffected
	case dtos.VulnStateAccepted:
		return vex.StatusAffected
	case dtos.VulnStateMarkedForTransfer:
		return vex.StatusAffected
	default:
		return vex.StatusUnderInvestigation
	}
}

func (s *assetVersionService) BuildOpenVeX(asset models.Asset, assetVersion models.AssetVersion, organizationSlug string, dependencyVulns []models.DependencyVuln) vex.VEX {
	doc := vex.New()

	doc.Author = organizationSlug
	doc.Timestamp = utils.Ptr(time.Now())
	doc.Statements = make([]vex.Statement, 0)

	appPurl := fmt.Sprintf("pkg:oci/%s/%s@%s", organizationSlug, asset.Slug, assetVersion.Slug)
	for _, dependencyVuln := range dependencyVulns {
		statement := vex.Statement{
			ID:              dependencyVuln.CVE.CVE,
			Status:          dependencyVulnToOpenVexStatus(dependencyVuln),
			ImpactStatement: utils.OrDefault(getJustification(dependencyVuln), ""),
			Vulnerability: vex.Vulnerability{
				ID:          fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", dependencyVuln.CVE.CVE),
				Name:        vex.VulnerabilityID(dependencyVuln.CVE.CVE),
				Description: dependencyVuln.CVE.Description,
			},
			Products: []vex.Product{{
				Component: vex.Component{
					ID: appPurl,
					Identifiers: map[vex.IdentifierType]string{
						vex.PURL: appPurl,
					},
				},
			}},
		}

		doc.Statements = append(doc.Statements, statement)
	}

	doc.GenerateCanonicalID() // nolint:errcheck
	return doc
}

func (s *assetVersionService) BuildVeX(frontendURL string, organizationName string, organizationSlug string, projectSlug string, asset models.Asset, assetVersion models.AssetVersion, artifactName string, dependencyVulns []models.DependencyVuln) *normalize.SBOMGraph {
	vulnerabilities := make([]cdx.Vulnerability, 0)
	for _, dependencyVuln := range dependencyVulns {
		// check if cve
		cve := dependencyVuln.CVE

		firstIssued, lastUpdated, firstResponded := getDatesForVulnerabilityEvent(dependencyVuln.Events)
		vuln := cdx.Vulnerability{
			ID: cve.CVE,
			Source: &cdx.Source{
				Name: "NVD",
				URL:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", dependencyVuln.CVEID),
			},
			Affects: &[]cdx.Affects{{
				Ref: dependencyVuln.ComponentPurl,
			}},
			Analysis: &cdx.VulnerabilityAnalysis{
				State:       dependencyVulnStateToImpactAnalysisState(dependencyVuln.State),
				FirstIssued: firstIssued.UTC().Format(time.RFC3339),
				LastUpdated: lastUpdated.UTC().Format(time.RFC3339),
			},
		}
		if !firstResponded.IsZero() {
			vuln.Properties = &[]cdx.Property{{Name: "firstResponded", Value: firstResponded.UTC().Format(time.RFC3339)}}
		}

		response := dependencyVulnStateToResponseStatus(dependencyVuln.State)
		if response != "" {
			vuln.Analysis.Response = &[]cdx.ImpactAnalysisResponse{response}
		}

		justification := getJustification(dependencyVuln)
		if justification != nil {
			vuln.Analysis.Detail = *justification
		} else if response == cdx.IARUpdate {
			vuln.Analysis.Detail = "Update available! Please update to the fixed version."
		}

		cvss := math.Round(float64(cve.CVSS)*100) / 100

		risk := vulndb.RawRisk(cve, shared.GetEnvironmentalFromAsset(asset), max(len(dependencyVuln.VulnerabilityPath), 1))

		vuln.Ratings = &[]cdx.VulnerabilityRating{
			{
				Vector:   cve.Vector,
				Method:   vectorToCVSSScoringMethod(cve.Vector),
				Score:    &cvss,
				Severity: scoreToSeverity(cvss),
			},
			{
				Vector:        risk.Vector,
				Method:        "DevGuard",
				Score:         &risk.Risk,
				Severity:      scoreToSeverity(risk.Risk),
				Justification: risk.String(),
			},
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	return normalize.SBOMGraphFromVulnerabilities(vulnerabilities)
}

func scoreToSeverity(score float64) cdx.Severity {
	if score >= 9.0 {
		return cdx.SeverityCritical
	} else if score >= 7.0 {
		return cdx.SeverityHigh
	} else if score >= 4.0 {
		return cdx.SeverityMedium
	}
	return cdx.SeverityLow
}

func vectorToCVSSScoringMethod(vector string) cdx.ScoringMethod {
	if strings.Contains(vector, "CVSS:3.0") {
		return cdx.ScoringMethodCVSSv3
	} else if strings.Contains(vector, "CVSS:2.0") {
		return cdx.ScoringMethodCVSSv2
	} else if strings.Contains(vector, "CVSS:3.1") {
		return cdx.ScoringMethodCVSSv31
	}
	return cdx.ScoringMethodCVSSv4
}

func dependencyVulnStateToImpactAnalysisState(state dtos.VulnState) cdx.ImpactAnalysisState {
	switch state {
	case dtos.VulnStateOpen:
		return cdx.IASInTriage
	case dtos.VulnStateFixed:
		return cdx.IASExploitable
	case dtos.VulnStateAccepted:
		return cdx.IASExploitable
	case dtos.VulnStateFalsePositive:
		return cdx.IASFalsePositive
	case dtos.VulnStateMarkedForTransfer:
		return cdx.IASInTriage
	default:
		return cdx.IASInTriage
	}
}

func getJustification(dependencyVuln models.DependencyVuln) *string {
	// check if we have any event
	if len(dependencyVuln.Events) > 0 {
		// look for the last event which has a justification
		for i := len(dependencyVuln.Events) - 1; i >= 0; i-- {
			if dependencyVuln.Events[i].Type != dtos.EventTypeRawRiskAssessmentUpdated && dependencyVuln.Events[i].Type != dtos.EventTypeComment && dependencyVuln.Events[i].Justification != nil {
				return dependencyVuln.Events[i].Justification
			}
		}
	}
	return nil
}

func dependencyVulnStateToResponseStatus(state dtos.VulnState) cdx.ImpactAnalysisResponse {
	switch state {
	case dtos.VulnStateOpen:
		return ""
	case dtos.VulnStateFixed:
		return cdx.IARUpdate
	case dtos.VulnStateAccepted:
		return cdx.IARWillNotFix
	case dtos.VulnStateFalsePositive:
		return cdx.IARWillNotFix
	case dtos.VulnStateMarkedForTransfer:
		return ""
	default:
		return ""
	}
}

func getDatesForVulnerabilityEvent(vulnEvents []models.VulnEvent) (time.Time, time.Time, time.Time) {
	firstIssued := time.Time{}
	lastUpdated := time.Time{}
	firstResponded := time.Time{}
	if len(vulnEvents) > 0 {
		firstIssued = time.Now()
		// find the date when the vulnerability was detected/created in the database
		for _, event := range vulnEvents {
			if event.Type == dtos.EventTypeDetected {
				firstIssued = event.CreatedAt
				break
			}
		}

		// in case no manual events are available we need to set the default to the firstIssued date
		lastUpdated = firstIssued

		// find the newest/latest event that was triggered through a human / manual interaction
		for _, event := range vulnEvents {
			// only manual events
			if event.Type == dtos.EventTypeFixed ||
				event.Type == dtos.EventTypeReopened ||
				event.Type == dtos.EventTypeAccepted ||
				event.Type == dtos.EventTypeMitigate ||
				event.Type == dtos.EventTypeFalsePositive ||
				event.Type == dtos.EventTypeMarkedForTransfer ||
				event.Type == dtos.EventTypeComment {
				if event.UpdatedAt.After(lastUpdated) {
					lastUpdated = event.UpdatedAt
				}
				if firstResponded.IsZero() {
					firstResponded = event.UpdatedAt
				} else if event.UpdatedAt.Before(firstResponded) {
					firstResponded = event.UpdatedAt
				}
			}
		}
	}

	return firstIssued, lastUpdated, firstResponded
}

// write the components from bom to the output file following the template
func MarkdownTableFromSBOM(outputFile *bytes.Buffer, bom *cdx.BOM) error {
	type componentData struct {
		Package  string
		Version  string
		Licenses []string
	}

	ecosystemCounts := make(map[string]int)
	licenseCounts := make(map[string]int)
	totalComponents := 0

	var templateValues []componentData
	for _, component := range *bom.Components {
		packageName := component.BOMRef

		// parse PURL to extract ecosystem for counting, but keep original packageName intact
		packageurlParsed, err := packageurl.FromString(component.PackageURL)
		if err != nil {
			continue
		}

		// count ecosystem
		ecosystemCounts[packageurlParsed.Type]++
		totalComponents++

		// count licenses
		if component.Licenses != nil && len(*component.Licenses) > 0 {
			for _, licenseChoice := range *component.Licenses {
				if licenseChoice.License != nil {
					if licenseChoice.License.ID != "" {
						licenseCounts[licenseChoice.License.ID]++
					}
				}
			}
		} else {
			licenseCounts["Unknown"]++
		}

		var licenseIDs []string
		if component.Licenses != nil && len(*component.Licenses) > 0 {
			for _, licenseChoice := range *component.Licenses {
				if licenseChoice.License != nil && licenseChoice.License.ID != "" {
					licenseIDs = append(licenseIDs, licenseChoice.License.ID)
				}
			}
		}
		if len(licenseIDs) == 0 {
			licenseIDs = []string{" Unknown"}
		}

		templateValues = append(templateValues, componentData{
			Package:  packageName,
			Version:  component.Version,
			Licenses: licenseIDs,
		})
	}

	// create template data with statistics
	type statEntry struct {
		Name  string
		Count int
	}

	type templateData struct {
		Components      []componentData
		EcosystemStats  []statEntry
		LicenseStats    []statEntry
		TotalComponents int
		ArtifactName    string
		AssetVersion    string
		CreationDate    string
		Publisher       string
	}

	// convert maps to sorted slices
	ecosystemSlice := make([]statEntry, 0, len(ecosystemCounts))
	for name, count := range ecosystemCounts {
		ecosystemSlice = append(ecosystemSlice, statEntry{Name: name, Count: count})
	}

	licenseSlice := make([]statEntry, 0, len(licenseCounts))
	for name, count := range licenseCounts {
		licenseSlice = append(licenseSlice, statEntry{Name: name, Count: count})
	}

	// sort by count descending (highest first)
	slices.SortStableFunc(ecosystemSlice, func(a, b statEntry) int {
		return b.Count - a.Count
	})
	slices.SortStableFunc(licenseSlice, func(a, b statEntry) int {
		return b.Count - a.Count
	})

	data := templateData{
		Components:      templateValues,
		EcosystemStats:  ecosystemSlice,
		LicenseStats:    licenseSlice,
		TotalComponents: totalComponents,
		ArtifactName:    bom.Metadata.Component.Name,
		AssetVersion:    bom.Metadata.Component.Version,
		CreationDate:    bom.Metadata.Timestamp,
		Publisher:       bom.Metadata.Component.Publisher,
	}

	//create template for the sbom markdown table
	sbomTmpl, err := template.New("sbomTmpl").Funcs(template.FuncMap{
		"percentage": func(count, total int) float64 {
			if total == 0 {
				return 0
			}
			return float64(count) / float64(total) * 100.0
		},
	}).Parse(
		`# SBOM

## Overview

- **Artifact Name:** {{ .ArtifactName }}
- **Version:** {{ .AssetVersion }}
- **Created:** {{ .CreationDate }}
- **Publisher:** {{ .Publisher }}

## Statistics

### Ecosystem Distribution
Total Components: {{ .TotalComponents }}

| Ecosystem | Count | Percentage |
|-----------|-------|------------|
{{range .EcosystemStats}}| {{ .Name }} | {{ .Count }} | {{ printf "%.1f%%" (percentage .Count $.TotalComponents) }} |
{{end}}

### License Distribution
| License | Count | Percentage |
|---------|-------|------------|
{{range .LicenseStats}}| {{ .Name }} | {{ .Count }} | {{ printf "%.1f%%" (percentage .Count $.TotalComponents) }} |
{{end}}

\newpage
## Components

| Package 						  | Version | Licenses  |
|---------------------------------|---------|-------|
{{range .Components}}| {{ .Package }} | {{ .Version }} | {{if gt (len .Licenses) 0 }}{{ range .Licenses }}{{.}} {{end}}{{ else }} Unknown {{ end }} |
{{end}}`,
	)
	if err != nil {
		return err
	}
	//filling the template with data from the parsed components and write that to the outputFile
	return sbomTmpl.Execute(outputFile, data)
}

// generate the metadata used to generate the sbom-pdf and return it as struct
func CreateYAMLMetadata(organizationName string, assetName string, assetVersionName string) dtos.YamlMetadata {
	today := time.Now()
	title1, title2 := createTitles(assetName + "@" + assetVersionName)

	if organizationName == "opencode" {
		organizationName = "openCode"
	}

	// TO-DO: add sha hash to test the integrity
	return dtos.YamlMetadata{
		Vars: dtos.YamlVars{
			DocumentTitle:    "DevGuard Report",
			PrimaryColor:     "\"#FF5733\"",
			Version:          assetVersionName,
			TimeOfGeneration: fmt.Sprintf("%s. %s %s", strconv.Itoa(today.Day()), today.Month().String(), strconv.Itoa(today.Year())),
			ProjectTitle1:    title1,
			ProjectTitle2:    title2,
			OrganizationName: organizationName,
			Integrity:        "",
		},
	}
}

// Divide and/or crop the project name into two, max 14 characters long, strings, there is probably a more elegant way to do this
func createTitles(name string) (string, string) {
	const maxTitleLength = 14 //make the length easy changeable
	title1 := ""
	title2 := ""
	title1Full := false            //once a field has exceeded the length of title1 we can ignore title1 from there on
	fields := strings.Fields(name) //separate the words divided by white spaces
	for _, field := range fields {
		if title1 == "" { //we have to differentiate if A tittle is empty or not before using, because of the white spaces between words in a title
			if len(field) <= maxTitleLength { //if it fits the 14 char limit we can just write it and move to the next
				title1 = field
			} else { //if not we know it won't fit the second one as well so we break the word up using "-"
				title1 = field[:maxTitleLength-1] + "-"
				title1Full = true                                    //we flag title1 as full
				if len(field[maxTitleLength-1:]) <= maxTitleLength { //now we need to append the rest of the word after "-"
					title2 = field[maxTitleLength-1:] //if the rest fits into the 14 char limit we just write it there
				} else {
					title2 = field[maxTitleLength-1:2*maxTitleLength-3] + ".." //if not we need to truncate the last 2 chars and put a .. to symbolize the ending
					break                                                      //then we are done since we know nothing fits anymore
				}
			}
		} else { //title1 is not empty so we now work with whitespaces
			if !title1Full && len(title1)+1+len(field) <= maxTitleLength { //add +1 because we need to account for an inserted white space
				title1 = title1 + " " + field
			} else { //if the field does not fit we move to the second title2 and here we again have to first check if its empty
				if title2 == "" {
					if len(field) <= maxTitleLength { //same as above
						title2 = field
					} else {
						title2 = field[:maxTitleLength-2] + ".." //same as above
						break
					}
				} else { //if its not empty we again try to put new fields into title2 until we are full
					if len(title2)+1+len(field) <= maxTitleLength { //it fits so we just write it in the title
						title2 = title2 + " " + field
					} else {
						if maxTitleLength-len(title2)-1 >= 4 { //if it doesn't fit we can only truncate like before if there are more than 3 remaining chars because we need 2 for the .. and 1 whitespace
							title2 = title2 + " " + field[:(maxTitleLength-3-len(title2))] + ".."
						}
						break //in either case we are done after this field
					}
				}
			}
		}
	}
	//now we return the two titles formatted correctly for the yaml file
	return title1, title2
}
