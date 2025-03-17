package utils

import (
	"bytes"
	"fmt"
	"log"
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
	Version       string
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

func SetGitVersionHeader(path string, req *http.Request) error {
	gitVersionInfo, err := GetAssetVersionInfoFromGit(path)
	if err != nil {
		return err
	}

	fmt.Println("Git Version Info: ", gitVersionInfo)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Asset-Version", gitVersionInfo.Version)
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
	}

	branchOrTag, err := getCurrentBranchName(path)
	if err != nil {
		return GitVersionInfo{}, errors.Wrap(err, "could not get branch name")
	}

	if commitAfterTag != 0 {
		version = version + "-" + strconv.Itoa(commitAfterTag)
	} else {
		// we are on a clean tag - use the tag as ref name
		branchOrTag = version
	}

	defaultBranch, err := getDefaultBranchName(path)
	if err != nil {
		return GitVersionInfo{}, errors.Wrap(err, "could not get default branch name")
	}

	return GitVersionInfo{
		Version:       version,
		BranchOrTag:   branchOrTag,
		DefaultBranch: defaultBranch,
	}, nil
}

func getCurrentBranchName(path string) (string, error) {
	// check if a CI variable is set - this provides a more stable way to get the branch name
	if os.Getenv("CI_COMMIT_REF_NAME") != "" {
		return os.Getenv("CI_COMMIT_REF_NAME"), nil
	}

	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err := cmd.Run()
	if err != nil {
		slog.Error("could not run git rev-parse --abbrev-ref HEAD", "err", err, "path", getDirFromPath(path), "msg", errOut.String())
		return "", err
	}

	return strings.TrimSpace(out.String()), nil
}

func getDefaultBranchName(path string) (string, error) {
	cmd := exec.Command("git", "remote", "show", "origin")
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err := cmd.Run()
	if err != nil {
		slog.Error("could not determine default branch", "err", err, "path", getDirFromPath(path), "msg", errOut.String())
		return "", err
	}

	parts := strings.Split(strings.TrimSpace(out.String()), "HEAD branch:")
	if len(parts) == 0 {
		return "", fmt.Errorf("unexpected format for default branch output")
	}
	parts = strings.Split(parts[1], "\n")
	if len(parts) == 0 {
		return "", fmt.Errorf("unexpected format for default branch output")
	}
	defaultBranch := strings.TrimSpace(parts[0])

	return defaultBranch, nil
}

func getCurrentVersion(path string) (string, int, error) {
	// mark the path as safe git directory
	slog.Debug("marking path as safe", "path", getDirFromPath(path))
	cmd := exec.Command("git", "config", "--global", "--add", "safe.directory", "*") // nolint:all
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err != nil {
		slog.Info("could not mark path as safe", "err", err, "path", getDirFromPath(path), "msg", errOut.String())
		return "", 0, err
	}

	// reset the buffer
	out.Reset()
	errOut.Reset()

	cmd = exec.Command("git", "tag")

	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err = cmd.Run()
	if err != nil {
		slog.Info("could not run git tag", "err", err, "path", getDirFromPath(path), "msg", errOut.String())
		return "", 0, err
	}

	// Filter using regex
	tagList := out.String()
	tags := strings.Split(tagList, "\n")
	// remove all tags which are not a valid semver
	tags = Filter(Map(tags, func(el string) string {
		return strings.TrimPrefix(el, "v")
	}), func(tag string) bool {
		return normalize.ValidSemverRegex.MatchString(tag)
	})

	// Sort the tags
	normalize.SemverSort(tags)
	if len(tags) == 0 {
		// no semver tags found
		cmd = exec.Command("git", "rev-list", "--count", "HEAD")
		var commitOut bytes.Buffer
		errOut = bytes.Buffer{}
		cmd.Stdout = &commitOut
		cmd.Stderr = &errOut
		cmd.Dir = getDirFromPath(path)
		err = cmd.Run()
		if err != nil {
			slog.Error(
				"could not run git rev-list --count", "err", err, "path", getDirFromPath(path), "msg", errOut.String(),
			)
			log.Fatal(err)
		}

		commitCounts := strings.TrimSpace(commitOut.String())
		commitCountsInt, err := strconv.Atoi(commitCounts)
		if err != nil {
			return "", 0, err
		}
		return "0.0.0", commitCountsInt, nil
	}

	// reverse the tags
	for i := 0; i < len(tags)/2; i++ {
		opp := len(tags) - i - 1
		tags[i], tags[opp] = tags[opp], tags[i]
	}
	latestTag := tags[0]

	fmt.Println("Latest Tag: ", latestTag)

	cmd = exec.Command("git", "rev-list", "--count", "v"+latestTag+"..HEAD") // nolint:all:Latest Tag is already checked against a semver regex.
	var commitOut bytes.Buffer
	errOut = bytes.Buffer{}
	cmd.Stdout = &commitOut
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err = cmd.Run()
	if err != nil {
		slog.Error(
			"could not run git rev-list --count", "err", err, "path", getDirFromPath(path), "msg", errOut.String(),
		)
		log.Fatal(err)
	}

	commitCount := strings.TrimSpace(commitOut.String())
	commitCountInt, err := strconv.Atoi(commitCount)
	if err != nil {
		return "", 0, err
	}

	return latestTag, commitCountInt, nil

}
