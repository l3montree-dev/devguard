package integrations

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

func cloneAndPushRepo(sshAuthKeys *gitssh.PublicKeys, projectName string, templatePath string) error {
	dir, err := os.MkdirTemp("", "repo-clone")
	if err != nil {
		return fmt.Errorf("could not create temporary directory: %v", err)
	}
	defer os.RemoveAll(dir) // Clean up after the test

	r, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL:  "git@gitlab.com:" + projectName + ".git",
		Auth: sshAuthKeys,
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
	f, err := w.Filesystem.OpenFile(".gitlab-ci.yml", os.O_RDWR, 0644)
	if err != nil {
		//make the file
		f, err = w.Filesystem.Create(".gitlab-ci.yml")
		if err != nil {
			return fmt.Errorf("could not create file: %v", err)
		}
		_, err = f.Write([]byte(template))
		if err != nil {
			return fmt.Errorf("could not write to file: %v", err)
		}
	} else {
		content, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("could not read file: %v", err)
		}
		fileStr := addPipelineTemplate(content, template)
		_, err = f.Write([]byte(fileStr))
		if err != nil {
			return fmt.Errorf("could not write to file: %v", err)
		}
	}
	f.Close()

	//push the changes
	_, err = w.Add(".gitlab-ci.yml")
	if err != nil {
		return fmt.Errorf("could not add file: %v", err)
	}
	_, err = w.Commit("Add devguard pipeline template", &git.CommitOptions{})
	if err != nil {
		return fmt.Errorf("could not commit: %v", err)
	}

	err = r.Push(&git.PushOptions{
		Auth: sshAuthKeys,
	})
	if err != nil {
		return fmt.Errorf("could not push: %v", err)
	}

	return nil
}
func addPipelineTemplate(file []byte, template string) string {
	fileStr := string(file)
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
		fileStr += `include:` + template
	}

	return fileStr
}
