package commonint

import (
	"bytes"
	"fmt"
	"html/template"
	"math/rand"
	"os"
	"strings"
	"time"

	_ "embed"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/shared"
)

func CreateNewVulnEventBasedOnComment(vulnID string, vulnType models.VulnType, userID, comment string, artifactName string) models.VulnEvent {

	event, mechanicalJustification, justification := commentTrimmedPrefix(vulnType, comment)

	switch event {
	case models.EventTypeAccepted:
		return models.NewAcceptedEvent(vulnID, vulnType, userID, justification, models.UpstreamStateInternal)
	case models.EventTypeFalsePositive:
		return models.NewFalsePositiveEvent(vulnID, vulnType, userID, justification, mechanicalJustification, artifactName, models.UpstreamStateInternal)
	case models.EventTypeReopened:
		return models.NewReopenedEvent(vulnID, vulnType, userID, justification, models.UpstreamStateInternal)
	case models.EventTypeComment:
		return models.NewCommentEvent(vulnID, vulnType, userID, comment)
	}

	return models.VulnEvent{}
}

func commentTrimmedPrefix(vulnType models.VulnType, comment string) (models.VulnEventType, models.MechanicalJustificationType, string) {

	comment = strings.TrimSpace(strings.TrimPrefix(comment, "`"))
	comment = strings.TrimSpace(strings.TrimSuffix(comment, "`"))

	if strings.HasPrefix(comment, "/component-not-present") && vulnType == models.VulnTypeDependencyVuln {
		return models.EventTypeFalsePositive, models.ComponentNotPresent, strings.TrimSpace(strings.TrimPrefix(comment, "/component-not-present"))
	} else if strings.HasPrefix(comment, "/vulnerable-code-not-present") && vulnType == models.VulnTypeDependencyVuln {
		return models.EventTypeFalsePositive, models.VulnerableCodeNotPresent, strings.TrimSpace(strings.TrimPrefix(comment, "/vulnerable-code-not-present"))
	} else if strings.HasPrefix(comment, "/vulnerable-code-not-in-execute-path") && vulnType == models.VulnTypeDependencyVuln {
		return models.EventTypeFalsePositive, models.VulnerableCodeNotInExecutePath, strings.TrimSpace(strings.TrimPrefix(comment, "/vulnerable-code-not-in-execute-path"))
	} else if strings.HasPrefix(comment, "/vulnerable-code-cannot-be-controlled-by-adversary") && vulnType == models.VulnTypeDependencyVuln {
		return models.EventTypeFalsePositive, models.VulnerableCodeCannotBeControlledByAdversary, strings.TrimSpace(strings.TrimPrefix(comment, "/vulnerable-code-cannot-be-controlled-by-adversary"))
	} else if strings.HasPrefix(comment, "/inline-mitigations-already-exist") && vulnType == models.VulnTypeDependencyVuln {
		return models.EventTypeFalsePositive, models.InlineMitigationsAlreadyExist, strings.TrimSpace(strings.TrimPrefix(comment, "/inline-mitigations-already-exist"))
	} else if strings.HasPrefix(comment, "/false-positive") && vulnType == models.VulnTypeFirstPartyVuln {
		return models.EventTypeFalsePositive, models.MechanicalJustificationType(strings.TrimSpace(strings.TrimPrefix(comment, "/false-positive"))), ""
	} else if strings.HasPrefix(comment, "/accept") {
		return models.EventTypeAccepted, "", strings.TrimSpace(strings.TrimPrefix(comment, "/accept"))
	} else if strings.HasPrefix(comment, "/reopen") {
		return models.EventTypeReopened, "", strings.TrimSpace(strings.TrimPrefix(comment, "/reopen"))
	}
	return models.EventTypeComment, "", comment
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

	//read the file
	//var newContent string
	//TODO: we should not read the file and then write it again, we should just append the include to the file and also check if all stages are present

	f, err := w.Filesystem.OpenFile(".gitlab-ci.yml", os.O_RDWR, 0644)
	if err != nil {
		//make the file
		f, err = w.Filesystem.Create(".gitlab-ci.yml")
		if err != nil {
			return fmt.Errorf("could not create file: %v", err)
		}
		//newContent = fmt.Sprintf("include:\n%s\n", template)
	} /*
		else {
			content, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("could not read file: %v", err)
			}
			newContent = addPipelineTemplate(content, template)
		}
	*/

	f.Close()
	// open the file in truncate mode to overwrite the content
	f, err = w.Filesystem.OpenFile(".gitlab-ci.yml", os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("could not open file: %v", err)
	}

	template, err := buildGitlabCiTemplate(templateID)
	if err != nil {
		return fmt.Errorf("could not build template: %v", err)
	}

	_, err = f.Write([]byte(template))

	if err != nil {
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

// this function returns a string containing a mermaids js flow chart to the given pURL
func RenderPathToComponent(componentRepository shared.ComponentRepository, assetID uuid.UUID, assetVersionName string, artifacts []models.Artifact, pURL string) (string, error) {
	artifactName := ""
	if len(artifacts) > 0 {
		artifactName = artifacts[0].ArtifactName
	}

	components, err := componentRepository.LoadPathToComponent(nil, assetVersionName, assetID, pURL, utils.EmptyThenNil(artifactName))
	if err != nil {
		return "", err
	}

	tree := normalize.BuildDependencyTree(models.ComponentDependencyNode{
		// nil will be mapped to empty string in BuildDepMap
		ID: "",
	}, utils.Flat(utils.Map(components, func(el models.ComponentDependency) []models.ComponentDependencyNode {
		return el.ToNodes()
	})), models.BuildDepMap(components))

	return tree.RenderToMermaid(), nil
}

func stateToLabel(state models.VulnState) string {
	switch state {
	case models.VulnStateFalsePositive:
		return "false-positive"
	case models.VulnStateAccepted:
		return "accepted"
	case models.VulnStateFixed:
		return "fixed"
	case models.VulnStateOpen:
		return "open"
	case models.VulnStateMarkedForTransfer:
		return "marked-for-transfer"
	}
	return "unknown"
}

func GetLabels(vuln models.Vuln) []string {
	labels := []string{
		"devguard",
		"state:" + stateToLabel(vuln.GetState()),
	}

	riskSeverity, err := risk.RiskToSeverity(vuln.GetRawRiskAssessment())
	if err == nil {
		labels = append(labels, "risk:"+strings.ToLower(riskSeverity))
	}

	if v, ok := vuln.(*models.DependencyVuln); ok {
		if v.CVE != nil {
			cvssSeverity, err := risk.RiskToSeverity(float64(v.CVE.CVSS))
			if err == nil {
				labels = append(labels, "cvss-severity:"+strings.ToLower(cvssSeverity))
			}
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

func AddPipelineTemplate(content []byte, template string) string { //nolint:unused
	fileStr := string(content)
	includeIndex := -1
	// split the file on each line
	for index, line := range strings.Split(fileStr, "\n") {
		// check if the line contains the include key
		if strings.Contains(line, "include:") {
			// include does exist
			includeIndex = index
			break
		}
	}

	if includeIndex != -1 {
		// insert it right after that index
		fileArr := strings.Split(fileStr, "\n")
		fileArr = append(fileArr[:includeIndex+1], append(strings.Split(template, "\n")[1:], fileArr[includeIndex+1:]...)...)
		fileStr = strings.Join(fileArr, "\n")
	} else {
		// include does not exist - just insert it at the end
		fileStr += fmt.Sprintf("\ninclude:\n%s\n", template)
	}

	return fileStr
}

func GenerateFourDigitNumber() int {
	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // we don't need a secure random number here
	return 1000 + r.Intn(9000)
}
