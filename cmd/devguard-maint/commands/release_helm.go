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

var ReleaseHelmCmd = &cobra.Command{
	Use:   "helm-chart <tag>",
	Short: "Update docker-compose and Helm chart, then commit, push, and tag",
	Args:  cobra.ExactArgs(1),
	RunE:  runReleaseHelm,
}

func runReleaseHelm(_ *cobra.Command, args []string) error {
	tag := args[0]
	semver, err := i.ValidateTag(tag)
	if err != nil {
		return err
	}
	minor := i.MinorVersion(tag)

	required := []string{
		"devguard",
		"devguard-web",
		"devguard/docker-compose-try-it.yaml",
		"devguard-helm-chart/Chart.yaml",
		"devguard-helm-chart/values.yaml",
	}
	for _, path := range required {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("%q does not exist", path)
		}
	}

	if err := i.CheckChangelogEntry(filepath.Join("devguard-helm-chart", "CHANGELOG.md"), tag); err != nil {
		return err
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

	for _, d := range []string{"devguard", "devguard-helm-chart"} {
		if err := i.GitCheckoutMain(d); err != nil {
			return fmt.Errorf("checkout main in %s: %w", d, err)
		}
		clean, err := i.GitIsClean(d)
		if err != nil {
			return err
		}
		if !clean {
			return fmt.Errorf("working directory %s is not clean", d)
		}
	}

	cl := &i.Changelog{}

	if err := updateDockerCompose(apiTag, webTag, cl); err != nil {
		return err
	}
	if err := updateHelmChart(tag, semver, apiTag, webTag, cl); err != nil {
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

	if err := i.GitAdd("devguard", "docker-compose-try-it.yaml"); err != nil {
		return err
	}
	if err := i.GitCommit("devguard", fmt.Sprintf("chore: update docker-compose-try-it.yaml (api=%s web=%s)", apiTag, webTag)); err != nil {
		return err
	}
	if err := i.GitPush("devguard"); err != nil {
		return err
	}
	cl.Change("Committed and pushed docker-compose-try-it.yaml")

	helmMsg := fmt.Sprintf(
		"chore: update Helm chart to %s\n\n- devguard image: %s\n- devguard-web image: %s\n- Helm chart version: %s, appVersion: %s",
		tag, apiTag, webTag, semver, tag,
	)
	if err := i.GitAdd("devguard-helm-chart", "."); err != nil {
		return err
	}
	if err := i.GitCommit("devguard-helm-chart", helmMsg); err != nil {
		return err
	}
	if err := i.GitPush("devguard-helm-chart"); err != nil {
		return err
	}
	cl.Change("Committed and pushed Helm chart")

	if err := i.GitTagSigned("devguard-helm-chart", tag); err != nil {
		cl.Fail("Failed to tag devguard-helm-chart: " + err.Error())
	} else {
		i.GitPushTags("devguard-helm-chart")
		cl.Change("Tagged devguard-helm-chart with " + tag)
	}

	cl.PrintSummary("FINAL SUMMARY")
	if cl.HasErrors() {
		return fmt.Errorf("completed with errors")
	}
	fmt.Println("\n✓ Script completed successfully!")
	return nil
}

func updateDockerCompose(apiTag, webTag string, cl *i.Changelog) error {
	path := "devguard/docker-compose-try-it.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Replace each image prefix independently so api and web get different tags.
	updated := string(data)
	type replacement struct {
		re  *regexp.Regexp
		tag string
	}
	replacements := []replacement{
		{regexp.MustCompile(`(ghcr\.io/l3montree-dev/devguard-web:)[^\s"]+`), webTag},
		{regexp.MustCompile(`(ghcr\.io/l3montree-dev/devguard/postgresql:)[^\s"]+`), apiTag},
		{regexp.MustCompile(`(ghcr\.io/l3montree-dev/devguard:)[^\s"]+`), apiTag},
	}
	for _, r := range replacements {
		updated = r.re.ReplaceAllStringFunc(updated, func(m string) string {
			idx := strings.LastIndex(m, ":")
			return m[:idx+1] + r.tag
		})
	}

	if updated == string(data) {
		cl.Fail("No changes in docker-compose-try-it.yaml — verify image patterns")
		return nil
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return err
	}
	cl.Change(fmt.Sprintf("Updated docker-compose-try-it.yaml (api=%s, web=%s)", apiTag, webTag))
	return nil
}

func updateHelmChart(tag, semver, apiTag, webTag string, cl *i.Changelog) error {
	chartPath := "devguard-helm-chart/Chart.yaml"
	valuesPath := "devguard-helm-chart/values.yaml"

	_, err := i.ReplaceLineInFile(chartPath, func(line string) string {
		if regexp.MustCompile(`^version:\s`).MatchString(line) {
			return "version: " + semver
		}
		if regexp.MustCompile(`^appVersion:\s`).MatchString(line) {
			return "appVersion: " + tag
		}
		return line
	})
	if err != nil {
		return err
	}
	cl.Change(fmt.Sprintf("Updated Chart.yaml: version=%s appVersion=%s", semver, tag))

	// Track the current repository so each image gets the right tag.
	currentRepo := ""
	_, err = i.ReplaceLineInFile(valuesPath, func(line string) string {
		if strings.Contains(line, "repository:") {
			if strings.Contains(line, "ghcr.io/l3montree-dev/") {
				currentRepo = line
			} else {
				currentRepo = ""
			}
		}
		if currentRepo != "" && regexp.MustCompile(`^\s+tag:\s`).MatchString(line) {
			var t string
			if strings.Contains(currentRepo, "devguard-web") {
				t = webTag
			} else {
				t = apiTag
			}
			return regexp.MustCompile(`tag:.*`).ReplaceAllString(line, "tag: "+t)
		}
		return line
	})
	if err != nil {
		return err
	}
	cl.Change(fmt.Sprintf("Updated values.yaml image tags (api=%s, web=%s)", apiTag, webTag))

	rawURLRe := regexp.MustCompile(`gitlab\.com/l3montree/devguard/-/raw/[^"]+`)
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return err
	}
	updated := rawURLRe.ReplaceAllStringFunc(string(data), func(m string) string {
		return regexp.MustCompile(`/raw/[^/]+`).ReplaceAllString(m, "/raw/"+tag)
	})
	if updated != string(data) {
		if err := os.WriteFile(valuesPath, []byte(updated), 0o644); err != nil {
			return err
		}
		cl.Change("Updated values.yaml ciComponentBase to " + tag)
	} else {
		cl.Fail("No ciComponentBase URL changes in values.yaml")
	}

	return nil
}
