package integrations

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-yaml/yaml"
	"github.com/xanzy/go-gitlab"
)

var pat string = ""

type pipe struct {
	stages []string
}

func TestX(t *testing.T) {
	privateKey, publicKeySsh, err := generateECDSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	client, err := gitlab.NewClient(pat, gitlab.WithBaseURL("https://gitlab.com"))
	if err != nil {
		t.Fatal(err)
	}

	tmpSSHKey, _, err := client.Users.AddSSHKey(&gitlab.AddSSHKeyOptions{
		Title: gitlab.Ptr("Devguard temp key"),
		Key:   gitlab.Ptr(publicKeySsh),
	})
	if err != nil {
		t.Fatal(err)
	}

	sshAuthKeys, err := gitssh.NewPublicKeys("git", []byte(privateKey), "")
	if err != nil {
		t.Fatal(err)
	}

	// Create a temporary directory for the worktree
	dir, err := os.MkdirTemp("", "repo-clone")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // Clean up after the test

	r, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL:  "git@gitlab.com:l3montree/lab/email-flood-casualty-generator.git",
		Auth: sshAuthKeys,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = r.CreateBranch(&config.Branch{
		Name: "devguard-autosetup",
	})
	if err != nil {
		t.Fatal(err)
	}
	//go to the branch
	w, err := r.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	err = w.Checkout(&git.CheckoutOptions{
		Branch: "refs/heads/devguard-autosetup",
		Create: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	//read the file
	f, err := w.Filesystem.Open(".gitlab-ci.yml")
	if err != nil {
		//make the file
		f, err = w.Filesystem.Create(".gitlab-ci.yml")
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write([]byte(""))
		if err != nil {
			t.Fatal(err)
		}
	} else {
		ymalFile := make(map[string]interface{})
		err = yaml.NewDecoder(f).Decode(&ymalFile)
		if err != nil {
			t.Fatal(err)
		}

		t.Error(ymalFile)
	}

	f.Close()

	tmpSSHKeyID := tmpSSHKey.ID
	_, err = client.Users.DeleteSSHKey(tmpSSHKeyID)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(r)
}

func TestX2(t *testing.T) {
	file, err := os.ReadFile("./test.yml")
	if err != nil {
		t.Fatal(err)
	}

	template := `
  - component: $CI_SERVER_FQDN/$CI_PROJECT_PATH/sca@$CI_COMMIT_SHA
    inputs:
      asset_name: "$DEVGUARD_ASSET_NAME"
      token: "$DEVGUARD_TOKEN"
      #You can change this to the desired stage. Make sure it matches one of your defined stages.
      scan_stage: test 

  - component: $CI_SERVER_FQDN/$CI_PROJECT_PATH/container-scanning@$CI_COMMIT_SHA
    inputs:
      asset_name: "$DEVGUARD_ASSET_NAME"
      token: "$DEVGUARD_TOKEN"
      #You can change these to the desired stages. Make sure they match one of your defined stages.
      scan_stage: test
      build_stage: "build"`

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

	err = os.WriteFile("./test.yml", []byte(fileStr), 0644)
	if err != nil {
		t.Fatal(err)
	}
}

type stages struct {
	Stages []string `yaml:"stages"`
}

func TestX3(t *testing.T) {
	file, err := os.ReadFile("./test.yml")
	if err != nil {
		t.Fatal(err)
	}

	template := `
  - build
  - test`

	stages := stages{}
	err = yaml.Unmarshal(file, &stages)
	if err != nil {
		t.Fatal(err)
	}
	testExist := false
	buildExist := false

	for _, stage := range stages.Stages {
		fmt.Println(stage)
		if stage == "build" {
			buildExist = true
		} else if stage == "test" {
			testExist = true
		}
	}

	fileStr := string(file)
	includeIndex := -1
	// split the file on each line
	for index, line := range strings.Split(fileStr, "\n") {
		// check if the line contains the include key
		if strings.Contains(line, "stages:") {
			// include does exist
			includeIndex = index
			break
		}
	}

	if includeIndex != -1 {
		// insert it right after that index
		fileArr := strings.Split(fileStr, "\n")
		if !buildExist && !testExist {
			// insert template at the end
			fileArr = append(fileArr, strings.Split(template, "\n")...)
		} else if !buildExist {
			// insert build at the end
			fileArr = append(fileArr, "- build")
		} else if !testExist {
			// insert test at the end
			fileArr = append(fileArr, "- test")
		}

	} else {
		// stages does not exist - just insert it at the end
		fileStr += "\n" + `stages:` + template
	}

	err = os.WriteFile("./test.yml", []byte(fileStr), 0644)
	if err != nil {
		t.Fatal(err)
	}

	t.Fail()
}
