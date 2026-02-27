package commonint

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "embed"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"

	"gopkg.in/yaml.v3"
)

// receives an uri and matches the extension to supported extensions, if not valid or not supported we return txt extension
func getLanguage(URI string) string {

	extension := filepath.Ext(URI)
	switch extension {
	case ".go":
		extension = "go"
	case ".ts":
		extension = "typescript"
	case ".js":
		extension = "js"
	case ".java":
		extension = "java"
	case ".py":
		extension = "python"
	case ".c":
		extension = "c"
	case ".cpp":
		extension = "cpp"
	case ".hpp":
		extension = "cpp"
	case ".css":
		extension = "css"
	case ".cs":
		extension = "csharp"
	case ".json":
		extension = "json"
	case ".yaml":
		extension = "yaml"
	case ".html":
		extension = "html"
	case ".xml":
		extension = "xml"
	case ".sql":
		extension = "sql"
	case ".mak":
		extension = "make"
	default:
		extension = "txt"
	}
	return extension
}

func RenderMarkdownForFirstPartyVuln(firstPartyVuln models.FirstPartyVuln, baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug string) string {
	var str strings.Builder
	str.WriteString("## Vulnerability Description\n\n")
	str.WriteString(*firstPartyVuln.Message)

	snippet, err := transformer.FromJSONSnippetContents(firstPartyVuln)
	if err != nil {
		slog.Error("could not parse snippet contents", "error", err)
		return str.String()
	}
	extension := getLanguage(firstPartyVuln.URI)

	// dynamically change the headline to the amount of Snippets
	str.WriteString("\n\n")
	if len(snippet.Snippets) == 1 {
		str.WriteString("## Code Snippet\n")
	} else if len(snippet.Snippets) >= 2 {
		str.WriteString("## Code Snippets\n")
	}

	var locationString string
	for _, snippet := range snippet.Snippets {
		// check if there is a filename and snippet - if so, we can render that as well
		sanitizedSnippet := strings.ReplaceAll(snippet.Snippet, "+++\n", "")
		sanitizedSnippet = strings.ReplaceAll(sanitizedSnippet, "\n+++", "") //just to make sure
		str.WriteString("\n\n")
		str.WriteString("```" + extension + "\n")
		str.WriteString(sanitizedSnippet)
		str.WriteString("\n")
		str.WriteString("```\n")

		// build the link to the file and start line of the snippet
		link := fmt.Sprintf("[%s](../%s#L%d)", firstPartyVuln.URI, strings.TrimPrefix(firstPartyVuln.URI, "/"), snippet.StartLine)
		if snippet.StartLine == snippet.EndLine {
			locationString = fmt.Sprintf("**Found at:** %s\n**Line:** %d\n", link, snippet.StartLine)
		} else {
			locationString = fmt.Sprintf("**Found at:** %s\n**Lines:** %d - %d\n", link, snippet.StartLine, snippet.EndLine)
		}
		str.WriteString(locationString)
	}

	str.WriteString("\n\n")
	fmt.Fprintf(&str, "More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/code-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, firstPartyVuln.ID)

	utils.AddSlashCommandsToFirstPartyVuln(&str)

	return str.String()
}

func RenderMarkdownForLicenseRisk(licenseRisk models.LicenseRisk, baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug string) string {
	var str strings.Builder
	str.WriteString("## License Risk Description\n\n")
	fmt.Fprintf(&str, "The license of the component %s could not be determined or isn't [OSI-approved](https://opensource.org/licenses)!", licenseRisk.ComponentPurl)
	str.WriteString("\n\n")
	str.WriteString("To handle the risk, make a final license decision in DevGuard.")
	str.WriteString("\n\n")
	fmt.Fprintf(&str, "More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/license-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, licenseRisk.ID)

	//utils.AddSlashCommandsToFirstPartyVuln(&str) To-Do?

	return str.String()
}

func CreateNewVulnEventBasedOnComment(vulnID string, vulnType dtos.VulnType, userID, comment string, artifactName string) models.VulnEvent {

	event, mechanicalJustification, justification := commentTrimmedPrefix(vulnType, comment)

	switch event {
	case dtos.EventTypeAccepted:
		return models.NewAcceptedEvent(vulnID, vulnType, userID, justification, false)
	case dtos.EventTypeFalsePositive:
		return models.NewFalsePositiveEvent(vulnID, vulnType, userID, justification, mechanicalJustification, artifactName, false)
	case dtos.EventTypeReopened:
		return models.NewReopenedEvent(vulnID, vulnType, userID, justification, false)
	case dtos.EventTypeComment:
		return models.NewCommentEvent(vulnID, vulnType, userID, comment, false)
	}

	return models.VulnEvent{}
}

func commentTrimmedPrefix(vulnType dtos.VulnType, comment string) (dtos.VulnEventType, dtos.MechanicalJustificationType, string) {

	comment = strings.TrimSpace(strings.TrimPrefix(comment, "`"))
	comment = strings.TrimSpace(strings.TrimSuffix(comment, "`"))

	if strings.HasPrefix(comment, "/component-not-present") && vulnType == dtos.VulnTypeDependencyVuln {
		return dtos.EventTypeFalsePositive, dtos.ComponentNotPresent, strings.TrimSpace(strings.TrimPrefix(comment, "/component-not-present"))
	} else if strings.HasPrefix(comment, "/vulnerable-code-not-present") && vulnType == dtos.VulnTypeDependencyVuln {
		return dtos.EventTypeFalsePositive, dtos.VulnerableCodeNotPresent, strings.TrimSpace(strings.TrimPrefix(comment, "/vulnerable-code-not-present"))
	} else if strings.HasPrefix(comment, "/vulnerable-code-not-in-execute-path") && vulnType == dtos.VulnTypeDependencyVuln {
		return dtos.EventTypeFalsePositive, dtos.VulnerableCodeNotInExecutePath, strings.TrimSpace(strings.TrimPrefix(comment, "/vulnerable-code-not-in-execute-path"))
	} else if strings.HasPrefix(comment, "/vulnerable-code-cannot-be-controlled-by-adversary") && vulnType == dtos.VulnTypeDependencyVuln {
		return dtos.EventTypeFalsePositive, dtos.VulnerableCodeCannotBeControlledByAdversary, strings.TrimSpace(strings.TrimPrefix(comment, "/vulnerable-code-cannot-be-controlled-by-adversary"))
	} else if strings.HasPrefix(comment, "/inline-mitigations-already-exist") && vulnType == dtos.VulnTypeDependencyVuln {
		return dtos.EventTypeFalsePositive, dtos.InlineMitigationsAlreadyExist, strings.TrimSpace(strings.TrimPrefix(comment, "/inline-mitigations-already-exist"))
	} else if strings.HasPrefix(comment, "/false-positive") && vulnType == dtos.VulnTypeFirstPartyVuln {
		return dtos.EventTypeFalsePositive, dtos.MechanicalJustificationType(strings.TrimSpace(strings.TrimPrefix(comment, "/false-positive"))), ""
	} else if strings.HasPrefix(comment, "/accept") {
		return dtos.EventTypeAccepted, "", strings.TrimSpace(strings.TrimPrefix(comment, "/accept"))
	} else if strings.HasPrefix(comment, "/reopen") {
		return dtos.EventTypeReopened, "", strings.TrimSpace(strings.TrimPrefix(comment, "/reopen"))
	}
	return dtos.EventTypeComment, "", comment
}

//go:embed templates/full_template.yml.gotmpl
var fullTemplate string

func buildGitlabCiTemplate(templateID string) (string, error) {
	var templateFile string

	switch templateID {
	case "full":
		fallthrough
	default:
		templateFile = fullTemplate
	}

	tmpl, err := template.New("gitlab-ci-template").Parse(templateFile)
	if err != nil {
		return "", fmt.Errorf("could not parse template: %v", err)
	}

	output := bytes.NewBuffer(nil)

	err = tmpl.Execute(output, map[string]string{
		"DevGuardCiComponentBase": utils.OrDefault(utils.EmptyThenNil(os.Getenv("DEVGUARD_CI_COMPONENT_BASE")), "https://gitlab.com/l3montree/devguard/-/raw/main"),
		"DevGuardFrontendUrl":     utils.OrDefault(utils.EmptyThenNil(os.Getenv("FRONTEND_URL")), "app.devguard.org"),
	})

	if err != nil {
		return "", fmt.Errorf("could not execute template: %v", err)
	}

	return output.String(), nil
}

func SetupAndPushPipeline(accessToken string, gitlabURL string, projectName string, templateID string, branchName string) error {
	dir, err := os.MkdirTemp("", "repo-clone")
	if err != nil {
		return fmt.Errorf("could not create temporary directory: %v", err)
	}
	defer os.RemoveAll(dir) // Clean up after the test

	authentication := &http.BasicAuth{
		Username: "abc123", // yes, this can be anything except an empty string
		Password: accessToken,
	}

	r, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL:  gitlabURL + "/" + projectName + ".git",
		Auth: authentication,
	})
	if err != nil {
		return fmt.Errorf("could not clone repository: %v", err)
	}
	err = r.CreateBranch(&config.Branch{
		Name: branchName,
	})
	if err != nil {
		return fmt.Errorf("could not create branch: %v", err)
	}

	//go to the branch
	w, err := r.Worktree()
	if err != nil {
		return fmt.Errorf("could not get worktree: %v", err)
	}
	err = w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName(branchName),
		Create: true,
	})
	if err != nil {
		return fmt.Errorf("could not checkout branch: %v", err)
	}

	// Read existing file content if it exists.
	var existingContent []byte
	f, err := w.Filesystem.OpenFile(".gitlab-ci.yml", os.O_RDONLY, 0)
	if err == nil {
		existingContent, err = io.ReadAll(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("could not read file: %v", err)
		}
	}

	template, err := buildGitlabCiTemplate(templateID)
	if err != nil {
		return fmt.Errorf("could not build template: %v", err)
	}

	if len(existingContent) > 0 {
		template, err = mergeGitlabCiTemplate(existingContent, template)
		if err != nil {
			return fmt.Errorf("could not merge template with existing content: %v", err)
		}
	}

	// Create truncates the file if it exists, so no leftover bytes.
	f, err = w.Filesystem.Create(".gitlab-ci.yml")
	if err != nil {
		return fmt.Errorf("could not open file for writing: %v", err)
	}

	_, err = f.Write([]byte(template))
	if err != nil {
		f.Close()
		return fmt.Errorf("could not write to file: %v", err)
	}

	f.Close()

	//push the changes
	_, err = w.Add(".gitlab-ci.yml")
	if err != nil {
		return fmt.Errorf("could not add file: %v", err)
	}
	_, err = w.Commit("Add devguard pipeline template", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "DevGuard",
			Email: "",
			When:  time.Now(),
		},
	})

	if err != nil {
		return fmt.Errorf("could not commit: %v", err)
	}

	err = r.Push(&git.PushOptions{
		Auth: authentication,
	})
	if err != nil {
		return fmt.Errorf("could not push: %v", err)
	}

	return nil
}

// mergeGitlabCiTemplate merges the devguard CI template into an existing .gitlab-ci.yml
// by appending only missing stages and include entries. All other content, comments, and
// key ordering from the existing file are preserved.
func mergeGitlabCiTemplate(existingYAML []byte, templateYAML string) (string, error) {
	var existingDoc yaml.Node
	if err := yaml.Unmarshal(existingYAML, &existingDoc); err != nil {
		return "", fmt.Errorf("could not parse existing .gitlab-ci.yml: %w", err)
	}

	existingMapping := yamlDocumentMapping(&existingDoc)
	if existingMapping == nil {
		// Existing file is empty or not a mapping — use template as-is.
		return templateYAML, nil
	}

	var templateDoc yaml.Node
	if err := yaml.Unmarshal([]byte(templateYAML), &templateDoc); err != nil {
		return "", fmt.Errorf("could not parse template yaml: %w", err)
	}

	templateMapping := yamlDocumentMapping(&templateDoc)
	if templateMapping == nil {
		return string(existingYAML), nil
	}

	// Merge stages — deduplicate by scalar value.
	mergeYAMLSequenceKey(existingMapping, templateMapping, "stages", func(a, b *yaml.Node) bool {
		return a.Kind == yaml.ScalarNode && b.Kind == yaml.ScalarNode && a.Value == b.Value
	})

	// Merge include — deduplicate by remote URL.
	mergeYAMLSequenceKey(existingMapping, templateMapping, "include", func(a, b *yaml.Node) bool {
		ra := yamlMappingScalarValue(a, "remote")
		rb := yamlMappingScalarValue(b, "remote")
		return ra != "" && ra == rb
	})

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&existingDoc); err != nil {
		return "", fmt.Errorf("could not marshal merged yaml: %w", err)
	}

	return strings.TrimPrefix(buf.String(), "---\n"), nil
}

// yamlDocumentMapping returns the top-level MappingNode from a DocumentNode, or nil.
func yamlDocumentMapping(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 && doc.Content[0].Kind == yaml.MappingNode {
		return doc.Content[0]
	}
	return nil
}

// yamlMappingScalarValue finds a scalar value for key in a MappingNode, or "".
func yamlMappingScalarValue(node *yaml.Node, key string) string {
	if node.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key && node.Content[i+1].Kind == yaml.ScalarNode {
			return node.Content[i+1].Value
		}
	}
	return ""
}

// yamlMappingKeyIndex returns the Content index of a key node in a MappingNode, or -1.
func yamlMappingKeyIndex(mapping *yaml.Node, key string) int {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return i
		}
	}
	return -1
}

// mergeYAMLSequenceKey appends items from the template sequence into the existing sequence
// for the given key, skipping items where isDuplicate returns true.
// If the key is absent from the existing mapping, it is added wholesale from the template.
func mergeYAMLSequenceKey(existingMapping, templateMapping *yaml.Node, key string, isDuplicate func(existing, incoming *yaml.Node) bool) {
	tIdx := yamlMappingKeyIndex(templateMapping, key)
	if tIdx < 0 {
		return
	}
	templateSeq := templateMapping.Content[tIdx+1]
	if templateSeq.Kind != yaml.SequenceNode {
		return
	}

	eIdx := yamlMappingKeyIndex(existingMapping, key)
	if eIdx < 0 {
		// Key missing from existing — add the entire template sequence.
		existingMapping.Content = append(existingMapping.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"},
			templateSeq,
		)
		return
	}

	existingSeq := existingMapping.Content[eIdx+1]
	// Wrap a bare scalar (e.g. `include: single.yml`) into a sequence.
	if existingSeq.Kind == yaml.ScalarNode {
		scalar := *existingSeq
		existingSeq.Kind = yaml.SequenceNode
		existingSeq.Tag = "!!seq"
		existingSeq.Value = ""
		existingSeq.Content = []*yaml.Node{&scalar}
	}

	for _, incoming := range templateSeq.Content {
		dup := false
		for _, existing := range existingSeq.Content {
			if isDuplicate(existing, incoming) {
				dup = true
				break
			}
		}
		if !dup {
			existingSeq.Content = append(existingSeq.Content, incoming)
		}
	}
}

func escapeNodeID(s string) string {
	if s == "" || s == normalize.GraphRootNodeID {
		return "root"
	}
	// Creates a safe Mermaid node ID by removing special characters
	return strings.NewReplacer("@", "_", ":", "_", "/", "_", ".", "_", "-", "_").Replace(s)
}

// beautifyNodeLabel creates a more readable label for graph nodes
func beautifyNodeLabel(nodeID string) string {
	if nodeID == "" || nodeID == "root" || nodeID == "ROOT" || nodeID == normalize.GraphRootNodeID {
		return "Root"
	}

	// Check if it's an info source node (sbom:, vex:, csaf:)
	if strings.HasPrefix(nodeID, "sbom:") {
		parts := strings.Split(nodeID, "@")
		if len(parts) == 2 {
			origin := strings.TrimPrefix(parts[0], "sbom:")
			return fmt.Sprintf("SBOM (%s)", origin)
		}
		return "SBOM"
	}
	if strings.HasPrefix(nodeID, "vex:") {
		parts := strings.Split(nodeID, "@")
		if len(parts) == 2 {
			origin := strings.TrimPrefix(parts[0], "vex:")
			return fmt.Sprintf("VEX (%s)", origin)
		}
		return "VEX"
	}
	if strings.HasPrefix(nodeID, "csaf:") {
		parts := strings.Split(nodeID, "@")
		if len(parts) == 2 {
			origin := strings.TrimPrefix(parts[0], "csaf:")
			return fmt.Sprintf("CSAF (%s)", origin)
		}
		return "CSAF"
	}

	// Check if it's an artifact node
	if after, ok := strings.CutPrefix(nodeID, "artifact:"); ok {
		artifactName := after
		return artifactName
	}

	// Regular component - just escape @ sign
	return strings.ReplaceAll(nodeID, "@", "\\@")
}

func pathsToMermaid(paths [][]string) string {
	mermaidFlowChart := "mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\n"

	var builder strings.Builder
	builder.WriteString(mermaidFlowChart)

	var existingPaths = make(map[string]bool)

	for _, path := range paths {
		for i := 0; i < len(path)-1; i++ {
			fromLabel := path[i]
			toLabel := path[i+1]
			mermaidPath := fmt.Sprintf("%s([\"%s\"]) --- %s([\"%s\"])\n",
				escapeNodeID(fromLabel), beautifyNodeLabel(fromLabel), escapeNodeID(toLabel), beautifyNodeLabel(toLabel))
			if existingPaths[mermaidPath] {
				// skip if path already exists
				continue
			}
			existingPaths[mermaidPath] = true

			builder.WriteString(mermaidPath)
		}
	}

	return "```" + builder.String() + "\nclassDef default stroke-width:2px\n```\n"
}

// this function returns a string containing a mermaids js flow chart to the given pURL
func RenderPathToComponent(componentRepository shared.ComponentRepository, assetID uuid.UUID, assetVersionName string, pURL string) (string, error) {
	// Load all components for the asset version
	components, err := componentRepository.LoadComponents(nil, assetVersionName, assetID)
	if err != nil {
		return "", err
	}

	bom, err := normalize.SBOMGraphFromComponents(utils.MapType[normalize.GraphComponent](components), nil)
	if err != nil {
		return "", err
	}

	paths := bom.FindAllComponentOnlyPathsToPURL(pURL, 0)
	// we want to show fake nodes in the mermaid graph (root, artifact, info sources)
	pathWithFakeNodes := make([][]string, 0, len(paths))
	for _, path := range paths {
		pathWithFakeNodes = append(pathWithFakeNodes, path.ToStringSlice())
	}
	return pathsToMermaid(pathWithFakeNodes), nil
}

func stateToLabel(state dtos.VulnState) string {
	switch state {
	case dtos.VulnStateFalsePositive:
		return "false-positive"
	case dtos.VulnStateAccepted:
		return "accepted"
	case dtos.VulnStateFixed:
		return "fixed"
	case dtos.VulnStateOpen:
		return "open"
	case dtos.VulnStateMarkedForTransfer:
		return "marked-for-transfer"
	}
	return "unknown"
}

func GetLabels(vuln models.Vuln) []string {
	labels := []string{
		"devguard",
		"state:" + stateToLabel(vuln.GetState()),
	}

	riskSeverity, err := vulndb.RiskToSeverity(vuln.GetRawRiskAssessment())
	if err == nil {
		labels = append(labels, "risk:"+strings.ToLower(riskSeverity))
	}

	if v, ok := vuln.(*models.DependencyVuln); ok {
		cvssSeverity, err := vulndb.RiskToSeverity(float64(v.CVE.CVSS))
		if err == nil {
			labels = append(labels, "cvss-severity:"+strings.ToLower(cvssSeverity))
		}
	}

	namesString := vuln.GetScannerIDsOrArtifactNames()
	names := strings.Split(namesString, " ")
	scannerDefault := "github.com/l3montree-dev/devguard/cmd/devguard-scanner/"

	// the same logic how to get the artifact name is implemented in the frontend
	// so if you change it here, you need to change it there too
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		name = strings.TrimPrefix(name, scannerDefault)

		labels = append(labels, name)

	}

	return labels
}

type Label struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
}

func GetAllRiskLabelsWithColors() []Label {

	riskDescription := "Calculated risk of the vulnerability (based on CVSS, EPSS, and other factors)"

	return []Label{
		{
			Name:        "risk:critical",
			Color:       "#FF0000",
			Description: riskDescription,
		},
		{
			Name:        "risk:high",
			Color:       "#FFA500",
			Description: riskDescription,
		},
		{
			Name:        "risk:medium",
			Color:       "#FFFF00",
			Description: riskDescription,
		},
		{
			Name:        "risk:low",
			Color:       "#00FF00",
			Description: riskDescription,
		},
		{
			Name:        "cvss-severity:critical",
			Color:       "#FF0000",
			Description: "CVSS severity of the vulnerability",
		},
		{
			Name:        "cvss-severity:high",
			Color:       "#FFA500",
			Description: "CVSS severity of the vulnerability",
		},
		{
			Name:        "cvss-severity:medium",
			Color:       "#FFFF00",
			Description: "CVSS severity of the vulnerability",
		},
		{
			Name:        "cvss-severity:low",
			Color:       "#00FF00",
			Description: "CVSS severity of the vulnerability",
		},
	}
}

func GenerateFourDigitNumber() int {
	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // we don't need a secure random number here
	return 1000 + r.Intn(9000)
}
