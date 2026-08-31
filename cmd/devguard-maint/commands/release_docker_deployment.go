package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	i "github.com/l3montree-dev/devguard/cmd/devguard-maint/internal"
	"github.com/spf13/cobra"
)

var ReleaseDockerDeploymentCmd = &cobra.Command{
	Use:   "docker-deployment <tag>",
	Short: "Update devguard-docker-deployment, then commit and push",
	Args:  cobra.ExactArgs(1),
	RunE:  runReleaseDockerDeployment,
}

func runReleaseDockerDeployment(_ *cobra.Command, args []string) error {
	tag := args[0]
	if _, err := i.ValidateTag(tag); err != nil {
		return err
	}
	minor := i.MinorVersion(tag)

	required := []string{
		"devguard",
		"devguard-web",
		"devguard-docker-deployment/.env.example",
		"devguard-docker-deployment/CHANGELOG.md",
	}
	for _, path := range required {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("%q does not exist", path)
		}
	}

	// Require at least one devguard and devguard-web release with the same minor.
	apiTag, err := i.GitLatestTagWithMinor("devguard", minor)
	if err != nil {
		return fmt.Errorf("could not detect latest devguard tag for minor %s: %w", minor, err)
	}
	if apiTag == "" {
		return fmt.Errorf("no devguard release found with minor version %s — run 'release devguard' first", minor)
	}

	webTag, err := i.GitLatestTagWithMinor("devguard-web", minor)
	if err != nil {
		return fmt.Errorf("could not detect latest devguard-web tag for minor %s: %w", minor, err)
	}
	if webTag == "" {
		return fmt.Errorf("no devguard-web release found with minor version %s — run 'release web' first", minor)
	}

	fmt.Printf("✓ devguard latest tag for minor %s: %s\n", minor, apiTag)
	fmt.Printf("✓ devguard-web latest tag for minor %s: %s\n", minor, webTag)

	if err := i.GitCheckoutMain("devguard-docker-deployment"); err != nil {
		return fmt.Errorf("checkout main in devguard-docker-deployment: %w", err)
	}
	clean, err := i.GitIsClean("devguard-docker-deployment")
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory devguard-docker-deployment is not clean")
	}

	if err := i.EnsureDockerDeploymentChangelogEntry(filepath.Join("devguard-docker-deployment", "CHANGELOG.md"), tag, apiTag, webTag); err != nil {
		return err
	}

	cl := &i.Changelog{}

	composeChanged, err := updateDockerDeployment(apiTag, webTag, cl)
	if err != nil {
		return err
	}

	cl.PrintSummary("CHANGE SUMMARY - READY FOR APPROVAL")
	if cl.HasErrors() {
		fmt.Println("\nWARNING: Some changes may not have been applied. Review before continuing.")
	}

	if !i.Confirm("\nContinue with commit, push and tagging?") {
		fmt.Println("Operation cancelled.")
		return nil
	}

	deploymentClean, err := i.GitIsClean("devguard-docker-deployment")
	if err != nil {
		return err
	}
	if !deploymentClean {
		if err := i.GitAdd("devguard-docker-deployment", "."); err != nil {
			return err
		}
		if err := i.GitCommit("devguard-docker-deployment", fmt.Sprintf("chore: update .env.example and CHANGELOG.md (api=%s web=%s)", apiTag, webTag)); err != nil {
			return err
		}
		if err := i.GitPush("devguard-docker-deployment"); err != nil {
			return err
		}
		cl.Change("Committed and pushed devguard-docker-deployment changes")
	} else if !composeChanged {
		fmt.Println("devguard-docker-deployment already up to date — nothing to commit")
	}

	cl.PrintSummary("FINAL SUMMARY")
	if cl.HasErrors() {
		return fmt.Errorf("completed with errors")
	}
	fmt.Println("\n✓ Script completed successfully!")
	return nil
}

// updateDockerDeployment rewrites the pinned image tags in
// devguard-docker-deployment/.env.example. Returns whether the file's content
// actually changed on disk, so the caller can skip commit/push when it was
// already up to date (a distinct case from the tag variables not matching at
// all, which is a real failure).
func updateDockerDeployment(apiTag, webTag string, cl *i.Changelog) (bool, error) {
	path := "devguard-docker-deployment/.env.example"
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	// Replace each tag variable independently so api and web get different tags.
	updated := string(data)
	type replacement struct {
		re  *regexp.Regexp
		tag string
	}
	replacements := []replacement{
		{regexp.MustCompile(`(?m)^(DEVGUARD_API_TAG=).*$`), apiTag},
		{regexp.MustCompile(`(?m)^(DEVGUARD_WEB_TAG=).*$`), webTag},
		{regexp.MustCompile(`(?m)^(POSTGRESQL_TAG=).*$`), apiTag},
		{regexp.MustCompile(`(?m)^(KRATOS_TAG=).*$`), apiTag},
	}
	matched := false
	for _, r := range replacements {
		if r.re.MatchString(updated) {
			matched = true
		}
		updated = r.re.ReplaceAllStringFunc(updated, func(m string) string {
			idx := strings.Index(m, "=")
			return m[:idx+1] + r.tag
		})
	}
	if !matched {
		cl.Fail("No changes in devguard-docker-deployment/.env.example — verify tag variable names")
		return false, nil
	}

	if updated == string(data) {
		cl.Change(".env.example already up to date (api=" + apiTag + ", web=" + webTag + ")")
		return false, nil
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return false, err
	}
	cl.Change(fmt.Sprintf("Updated devguard-docker-deployment/.env.example (api=%s, web=%s)", apiTag, webTag))
	return true, nil
}
