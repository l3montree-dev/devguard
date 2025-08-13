package commonint

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

func CreateNewVulnEventBasedOnComment(vulnID string, vulnType models.VulnType, userID, comment string, scannerIDs string) models.VulnEvent {

	event, mechanicalJustification, justification := commentTrimmedPrefix(vulnType, comment)

	switch event {
	case models.EventTypeAccepted:
		return models.NewAcceptedEvent(vulnID, vulnType, userID, justification)
	case models.EventTypeFalsePositive:
		return models.NewFalsePositiveEvent(vulnID, vulnType, userID, justification, mechanicalJustification, scannerIDs)
	case models.EventTypeReopened:
		return models.NewReopenedEvent(vulnID, vulnType, userID, justification)
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

func SetupAndPushPipeline(accessToken string, gitlabURL string, projectName string, templatePath string, branchName string) error {
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

	templateFile, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("could not read template file: %v", err)
	}
	template := string(templateFile)

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
func RenderPathToComponent(componentRepository core.ComponentRepository, assetID uuid.UUID, assetVersionName string, scannerID string, pURL string) (string, error) {

	components, err := componentRepository.LoadPathToComponent(nil, assetVersionName, assetID, pURL, scannerID)
	if err != nil {
		return "", err
	}

	tree := assetversion.BuildDependencyTree(components, scannerID)
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

	scannerIDsString := vuln.GetScannerIDs()
	scannerIDs := strings.Split(scannerIDsString, " ")
	scannerDefault := "github.com/l3montree-dev/devguard/cmd/devguard-scanner/"

	// the same logic how to get the artifact name is implemented in the frontend
	// so if you change it here, you need to change it there too
	for _, scannerID := range scannerIDs {
		scannerID = strings.TrimSpace(scannerID)
		if scannerID == "" {
			continue
		}
		scannerID = strings.TrimPrefix(scannerID, scannerDefault)
		if strings.HasPrefix(scannerID, "sca") || strings.HasPrefix(scannerID, "container-scanning") || strings.HasPrefix(scannerID, "sbom") {
			artifactName := scannerID
			parts := strings.Split(scannerID, ":")
			if len(parts) > 0 {
				switch parts[0] {
				case "sca":
					artifactName = "source-code"
				case "container-scanning":
					artifactName = "container"
				case "sbom":
					artifactName = "sbom"
				}
			}
			if len(parts) > 1 {
				artifactName = artifactName + ":" + parts[1]
			}
			labels = append(labels, "artifact:"+artifactName)
		} else {
			labels = append(labels, scannerID)
		}
	}

	return labels
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
