package utils

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core/normalize"

	"github.com/pkg/errors"
)

type GitVersionInfo struct {
	BranchOrTag   string
	DefaultBranch string
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

var git gitLister = commandLineGitLister{}

func SetGitLister(g gitLister) {
	git = g
}

func SetGitVersionHeader(path string, req *http.Request) error {
	gitVersionInfo, err := GetAssetVersionInfoFromGit(path)
	if err != nil {
		if err.Error() == "could not get current version" {
		} else {
			return err
		}

	}

	fmt.Println("Git Version Info: ", gitVersionInfo)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Asset-Ref", gitVersionInfo.BranchOrTag)
	req.Header.Set("X-Asset-Default-Branch", gitVersionInfo.DefaultBranch)

	return nil
}

func GetAssetVersionInfoFromGit(path string) (GitVersionInfo, error) {
	// we use the commit count, to check if we should create a new version - or if its dirty.
	// v1.0.0 - . . . . . . . . . . - v1.0.1
	// all commits after v1.0.0 are part of v1.0.1
	// if there are no commits after the tag, we are on a clean tag

	version, commitAfterTag, err := getCurrentVersion(path)
	if err != nil {
		slog.Error("could not get current version", "err", err)
		return GitVersionInfo{}, errors.New("could not get current version")
	}

	branchOrTag, err := getCurrentBranchName(path)
	if err != nil {
		return GitVersionInfo{}, errors.Wrap(err, "could not get branch name")
	}

	if commitAfterTag == 0 {
		// we are on a clean tag - use the tag as ref name
		branchOrTag = version
	}

	defaultBranch, err := getDefaultBranchName(path)
	if err != nil {
		return GitVersionInfo{}, errors.Wrap(err, "could not get default branch name")
	}

	return GitVersionInfo{
		BranchOrTag:   branchOrTag,
		DefaultBranch: defaultBranch,
	}, nil
}

func getCurrentBranchName(path string) (string, error) {
	// check if a CI variable is set - this provides a more stable way to get the branch name
	if os.Getenv("CI_COMMIT_REF_NAME") != "" {
		return os.Getenv("CI_COMMIT_REF_NAME"), nil
	}

	return git.GetBranchName(path)
}

func getDefaultBranchName(path string) (string, error) {
	outString, err := git.GetDefaultBranchName(path)
	if err != nil {
		return "", err
	}

	parts := strings.Split(strings.TrimSpace(outString), "HEAD branch:")
	if len(parts) == 0 {
		return "", fmt.Errorf("unexpected format for default branch output")
	}
	if len(parts) == 1 {
		return strings.TrimSpace(parts[0]), nil
	}
	parts = strings.Split(parts[1], "\n")
	if len(parts) == 0 {
		return "", fmt.Errorf("unexpected format for default branch output")
	}
	defaultBranch := strings.TrimSpace(parts[0])

	return defaultBranch, nil
}

type gitLister interface {
	MarkAsSafePath(path string) error
	GetTags(path string) ([]string, error)
	GitCommitCount(path string, tag *string) (int, error)
	GetBranchName(path string) (string, error)
	GetDefaultBranchName(path string) (string, error)
}

type commandLineGitLister struct {
}

func (g commandLineGitLister) GetDefaultBranchName(path string) (string, error) {
	cmd := exec.Command("git", "remote", "show", "origin")
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return out.String(), nil

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

func (g commandLineGitLister) MarkAsSafePath(path string) error {
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
		m[el] = t
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
	err := git.MarkAsSafePath(path) // nolint:all
	if err != nil {
		slog.Info("could not mark path as safe", "err", err, "path", getDirFromPath(path), "msg", err.Error())
		return "", 0, err
	}

	// get tags from the git repository
	tags, err := git.GetTags(path)
	if err != nil {
		slog.Info("could not get tags", "err", err, "path", getDirFromPath(path), "msg", err.Error())
		return "", 0, err
	}

	// filter and sort the tags
	originalLatestTagName, latestTag, err := filterAndSortValidSemverTags(tags)
	if err != nil {
		//there is not a single valid semver tag
		commitCountsInt, err := git.GitCommitCount(path, nil)
		if err != nil {
			return "", 0, err
		}
		return "0.0.0", commitCountsInt, nil
	}

	// get the commit count
	commitCountsInt, err := git.GitCommitCount(path, &originalLatestTagName)
	if err != nil {
		return "", 0, err
	}

	return latestTag, commitCountsInt, nil

}
