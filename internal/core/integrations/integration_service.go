package integrations

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

func setupAndPushPipeline(accessToken string, projectName string, templatePath string) error {
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
		//URL:  "git@gitlab.com:" + projectName + ".git",
		URL:  "https://gitlab.com/" + projectName + ".git",
		Auth: authentication,
		//URL:  "https://gitlab.com/l3montree/bachelorarbeit.git",
	})
	if err != nil {
		return fmt.Errorf("could not clone repository: %v", err)
	}
	err = r.CreateBranch(&config.Branch{
		Name: "devguard-autosetup",
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
		Branch: "refs/heads/devguard-autosetup",
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
func addPipelineTemplate(content []byte, template string) string { //nolint:unused
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
