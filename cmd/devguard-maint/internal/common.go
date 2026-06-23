package internal

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var semverRe = regexp.MustCompile(`^v(\d+\.\d+\.\d+(?:-[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*)?)$`)
var bareSemverRe = regexp.MustCompile(`^\d+\.\d+\.\d+`)

func ValidateTag(tag string) (semver string, err error) {
	if m := semverRe.FindStringSubmatch(tag); m != nil {
		return m[1], nil
	}
	if bareSemverRe.MatchString(tag) {
		return "", fmt.Errorf("version must be prefixed with 'v' (e.g. v1.0.0)")
	}
	return "", fmt.Errorf("invalid version %q — use semantic versioning with 'v' prefix (e.g. v1.0.0)", tag)
}

// GitRun runs a git command in dir, forwarding stdout/stderr to the terminal.
func GitRun(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// gitOutput runs a git command and returns trimmed stdout (internal only).
func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func GitTagExists(dir, tag string) (bool, error) {
	out, err := gitOutput(dir, "tag", "--list", tag)
	if err != nil {
		return false, fmt.Errorf("git tag --list in %s: %w", dir, err)
	}
	return out == tag, nil
}

func GitCheckoutMain(dir string) error {
	return GitRun(dir, "checkout", "main")
}

func GitIsClean(dir string) (bool, error) {
	out, err := gitOutput(dir, "status", "--porcelain")
	if err != nil {
		return false, err
	}
	return out == "", nil
}

func GitPull(dir string) error {
	return GitRun(dir, "pull", "origin", "main")
}

func GitAdd(dir string, paths ...string) error {
	return GitRun(dir, append([]string{"add"}, paths...)...)
}

func GitCommit(dir, msg string) error {
	return GitRun(dir, "commit", "-m", msg)
}

func GitPush(dir string) error {
	return GitRun(dir, "push")
}

func GitTagSigned(dir, tag string) error {
	return GitRun(dir, "tag", "-s", tag, "-m", tag)
}

func GitPushTags(dir string) {
	_ = GitRun(dir, "push", "--tags")
}

func Confirm(prompt string) bool {
	fmt.Printf("%s (y/n) ", prompt)
	sc := bufio.NewScanner(os.Stdin)
	sc.Scan()
	return strings.ToLower(strings.TrimSpace(sc.Text())) == "y"
}

type Changelog struct {
	changes []string
	errors  []string
}

func (c *Changelog) Change(msg string) { c.changes = append(c.changes, "  ✓ "+msg) }
func (c *Changelog) Fail(msg string)   { c.errors = append(c.errors, "  ✗ "+msg) }
func (c *Changelog) HasErrors() bool   { return len(c.errors) > 0 }

func (c *Changelog) PrintSummary(title string) {
	fmt.Printf("\n╔═════════════════════════════════════════╗\n")
	fmt.Printf("║  %-41s║\n", title)
	fmt.Printf("╚═════════════════════════════════════════╝\n\n")
	fmt.Printf("Total changes: %d\n", len(c.changes))
	for _, ch := range c.changes {
		fmt.Println(ch)
	}
	if len(c.errors) > 0 {
		fmt.Println("\n⚠ Issues:")
		for _, e := range c.errors {
			fmt.Println(e)
		}
	}
}

// ReplaceInFile replaces all occurrences of old with new in the file at path.
// Returns whether the file was modified.
func ReplaceInFile(path, old, new string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	updated := strings.ReplaceAll(string(data), old, new)
	if updated == string(data) {
		return false, nil
	}
	return true, os.WriteFile(path, []byte(updated), 0o644)
}

// ReplaceLineInFile applies a per-line transform and writes back if changed.
func ReplaceLineInFile(path string, transform func(line string) string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(data), "\n")
	changed := false
	for i, l := range lines {
		if t := transform(l); t != l {
			lines[i] = t
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	return true, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}
