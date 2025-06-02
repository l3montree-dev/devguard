package utils

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core/normalize"

	"github.com/pkg/errors"
)

type GitVersionInfo struct {
	IsTag         bool
	BranchOrTag   string
	DefaultBranch *string
}

func getDirFromPath(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return path
	}
	switch mode := fi.Mode(); {
	case mode.IsDir():
		return path
	case mode.IsRegular():
		return filepath.Dir(path)
	}
	return path
}

var GitLister gitLister = commandLineGitLister{}

func getAssetVersionInfoFromPipeline() (GitVersionInfo, error) {
	var gitVersionInfo GitVersionInfo

	// check if a CI variable is set, so we can get the branch name
	branchName := os.Getenv("CI_COMMIT_REF_NAME")
	if branchName != "" {
		defaultBranch := os.Getenv("CI_DEFAULT_BRANCH")
		tagName := os.Getenv("CI_COMMIT_TAG")
		if tagName != "" {
			// we are on a tag - use the tag as ref name
			branchName = tagName
		}
		gitVersionInfo = GitVersionInfo{
			BranchOrTag:   branchName,
			IsTag:         tagName != "",
			DefaultBranch: EmptyThenNil(defaultBranch),
		}
		return gitVersionInfo, nil
	} else {
		// check if we are in a GitHub Action
		branchName = os.Getenv("GITHUB_REF_NAME")
		//This returns the short ref name of the branch or tag that triggered the workflow run.
		if branchName != "" {
			gitVersionInfo = GitVersionInfo{
				IsTag:         strings.HasPrefix(os.Getenv("GITHUB_REF"), "refs/tags/"),
				BranchOrTag:   branchName,
				DefaultBranch: nil, // there is no environment variable for the default branch in GitHub Actions
			}
			return gitVersionInfo, nil
		} else {
			return GitVersionInfo{}, errors.New("could not get branch name from environment variables")
		}
	}
}
func GetAssetVersionInfo(path string) (GitVersionInfo, error) {
	// first try to get the version info from the pipeline
	gitVersionInfo, err := getAssetVersionInfoFromPipeline()
	if err == nil {
		slog.Info("got git version info from pipeline", "branchOrTag", gitVersionInfo.BranchOrTag, "defaultBranch", SafeDereference(gitVersionInfo.DefaultBranch))
		return gitVersionInfo, nil
	}
	// if that fails, try to get the version info from git
	slog.Info("could not get git version info from pipeline, falling back to git")
	gitVersionInfo, err = getAssetVersionInfoFromGit(path)
	if err != nil {
		slog.Error("could not get git version info from git")
		return GitVersionInfo{}, errors.Wrap(err, "could not get git version info from git")
	}
	slog.Info("got git version info from git", "branchOrTag", gitVersionInfo.BranchOrTag, "defaultBranch", SafeDereference(gitVersionInfo.DefaultBranch))
	return gitVersionInfo, nil
}

func getAssetVersionInfoFromGit(path string) (GitVersionInfo, error) {
	// we use the commit count, to check if we should create a new version - or if its dirty.
	// v1.0.0 - . . . . . . . . . . - v1.0.1
	// all commits after v1.0.0 are part of v1.0.1
	// if there are no commits after the tag, we are on a clean tag
	version, commitAfterTag, err := getCurrentVersion(path)
	if err != nil {
		slog.Error("could not get current version", "err", err)
		return GitVersionInfo{}, errors.New("could not get current version")
	}

	branchOrTag, err := GitLister.GetBranchName(path)
	if err != nil {
		return GitVersionInfo{}, errors.Wrap(err, "could not get branch name")
	}

	if commitAfterTag == 0 {
		// we are on a clean tag - use the tag as ref name
		branchOrTag = version
	}

	defaultBranch, err := GitLister.GetDefaultBranchName(path)
	if err != nil {
		slog.Info("could not get default branch name", "err", err, "path", getDirFromPath(path), "msg", err.Error())
		return GitVersionInfo{
			BranchOrTag:   branchOrTag,
			DefaultBranch: nil,
			IsTag:         commitAfterTag == 0,
		}, nil
	}

	return GitVersionInfo{
		BranchOrTag:   branchOrTag,
		DefaultBranch: &defaultBranch,
		IsTag:         commitAfterTag == 0,
	}, nil
}

type gitLister interface {
	MarkAllPathsAsSafe() error
	GetTags(path string) ([]string, error)
	GitCommitCount(path string, tag *string) (int, error)
	GetBranchName(path string) (string, error)
	GetDefaultBranchName(path string) (string, error)
}

type commandLineGitLister struct {
}

func (g commandLineGitLister) GetDefaultBranchName(path string) (string, error) {
	// returns something like
	// "origin/main"

	cmd := exec.Command("git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err := cmd.Run()
	if err != nil {
		fmt.Println(errOut.String())
		return "", err
	}

	outStr := strings.TrimSpace(out.String())
	if outStr == "" {
		return "", fmt.Errorf("could not get default branch name")
	}
	// remove the "origin/" prefix
	return strings.TrimPrefix(outStr, "origin/"), nil
}

func (g commandLineGitLister) GetBranchName(path string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(out.String()), nil
}

func (g commandLineGitLister) MarkAllPathsAsSafe() error {
	cmd := exec.Command("git", "config", "--global", "--add", "safe.directory", "*")
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	return err
}

func (g commandLineGitLister) GetTags(path string) ([]string, error) {
	cmd := exec.Command("git", "tag")
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	tags := strings.Split(out.String(), "\n")
	return tags, nil
}

func (g commandLineGitLister) GitCommitCount(path string, tag *string) (int, error) {

	var cmd *exec.Cmd
	if tag != nil {
		cmd = exec.Command("git", "rev-list", "--count", *tag+"..HEAD") // nolint: gosec
	} else {
		cmd = exec.Command("git", "rev-list", "--count", "HEAD") // nolint: gosec
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err := cmd.Run()
	if err != nil {
		return 0, err
	}

	commitCount := strings.TrimSpace(out.String())
	commitCountInt, err := strconv.Atoi(commitCount)
	if err != nil {
		return 0, err
	}

	return commitCountInt, nil
}
func filterAndSortValidSemverTags(tags []string) (string, string, error) {

	m := map[string]string{}

	// Map the tags and populate the map
	mappedTags := Map(tags, func(el string) string {
		t := strings.TrimPrefix(el, "v")
		m[t] = el
		return t
	})

	// Filter the tags based on the regex
	filteredTags := Filter(mappedTags, func(tag string) bool {
		return normalize.ValidSemverRegex.MatchString(tag)
	})

	if len(filteredTags) == 0 {
		return "", "", errors.New("no valid semver tags found")
	}

	// Sort the tags
	normalize.SemverSort(filteredTags)
	for i := 0; i < len(filteredTags)/2; i++ {
		opp := len(filteredTags) - i - 1
		filteredTags[i], filteredTags[opp] = filteredTags[opp], filteredTags[i]
	}
	latestTag := filteredTags[0]
	originalLatestTagName := m[latestTag]

	return originalLatestTagName, latestTag, nil
}

func getCurrentVersion(path string) (string, int, error) {
	// mark the path as safe git directory
	slog.Debug("marking path as safe", "path", getDirFromPath(path))

	// get tags from the git repository
	tags, err := GitLister.GetTags(path)
	if err != nil {
		slog.Info("could not get tags", "err", err, "path", getDirFromPath(path), "msg", err.Error())
		return "", 0, err
	}

	// filter and sort the tags
	originalLatestTagName, latestTag, err := filterAndSortValidSemverTags(tags)
	if err != nil {
		//there is not a single valid semver tag
		commitCountsInt, err := GitLister.GitCommitCount(path, nil)
		if err != nil {
			return "", 0, err
		}
		return "0.0.0", commitCountsInt, nil
	}

	// get the commit count
	commitCountsInt, err := GitLister.GitCommitCount(path, &originalLatestTagName)
	if err != nil {
		return "", 0, err
	}

	return latestTag, commitCountsInt, nil

}

func ReadFileFromGitRef(path string, commitSha string, fileName string) ([]byte, error) {
	cmd := exec.Command("git", "show", fmt.Sprintf("%s:%s", commitSha, fileName)) // nolint:gosec // runs on the client. You are free to attack yourself

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err := cmd.Run()
	if err != nil {
		return nil, errors.Wrap(err, "could not run git command")
	}

	// read the file line by line
	bytes, err := io.ReadAll(&out)
	if err != nil {
		slog.Error("could not read file", "err", err)
		return nil, errors.Wrap(err, "could not read file")
	}

	return bytes, nil
}
