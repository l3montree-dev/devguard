package commands

import (
	"fmt"
	"os"
	"os/exec"
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
		"devguard-ci-components",
		"devguard-docker-deployment/.env.example",
		"devguard-docker-deployment/CHANGELOG.md",
		"devguard-helm-chart/Chart.yaml",
		"devguard-helm-chart/values.yaml",
		"devguard-helm-chart/schema/schema.ts",
	}
	for _, path := range required {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("%q does not exist", path)
		}
	}

	// Require at least one devguard, devguard-web, and devguard-ci-components
	// release with the same minor.
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

	ciComponentsTag, err := i.GitLatestTagWithMinor("devguard-ci-components", minor)
	if err != nil {
		return fmt.Errorf("could not detect latest devguard-ci-components tag for minor %s: %w", minor, err)
	}
	if ciComponentsTag == "" {
		return fmt.Errorf("no devguard-ci-components release found with minor version %s — run 'release ci-components' first", minor)
	}

	fmt.Printf("✓ devguard latest tag for minor %s: %s\n", minor, apiTag)
	fmt.Printf("✓ devguard-web latest tag for minor %s: %s\n", minor, webTag)
	fmt.Printf("✓ devguard-ci-components latest tag for minor %s: %s\n", minor, ciComponentsTag)

	for _, d := range []string{"devguard-docker-deployment", "devguard-helm-chart"} {
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

	if err := i.EnsureHelmChangelogEntry(filepath.Join("devguard-helm-chart", "CHANGELOG.md"), tag, apiTag, webTag, ciComponentsTag); err != nil {
		return err
	}
	if err := i.EnsureDockerDeploymentChangelogEntry(filepath.Join("devguard-docker-deployment", "CHANGELOG.md"), tag, apiTag, webTag); err != nil {
		return err
	}

	cl := &i.Changelog{}

	composeChanged, err := updateDockerDeployment(apiTag, webTag, cl)
	if err != nil {
		return err
	}
	if err := updateHelmChart(semver, apiTag, webTag, ciComponentsTag, cl); err != nil {
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

	helmMsg := fmt.Sprintf(
		"chore: update Helm chart to %s\n\n- devguard image: %s\n- devguard-web image: %s\n- devguard-ci-components: %s\n- kratos image: %s\n- Helm chart version: %s, appVersion: %s",
		tag, apiTag, webTag, ciComponentsTag, apiTag, semver, apiTag,
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

// updateHelmChart regenerates values.yaml, Chart.yaml, and questions.yaml from
// devguard-helm-chart/schema (see schema/schema.ts) by running `bun run
// generate` with the four version knobs it requires — one per independently
// released component, all confirmed present via EnsureHelmChangelogEntry /
// GitLatestTagWithMinor before this runs. kratos and postgresql are tagged
// and released alongside devguard (see nix/kratos.nix), so both track apiTag
// without a knob of their own (see devguard-helm-chart/schema/versions.ts).
func updateHelmChart(chartSemver, apiTag, webTag, ciComponentsTag string, cl *i.Changelog) error {
	cmd := exec.Command("bun", "run", "generate")
	cmd.Dir = "devguard-helm-chart/schema"
	cmd.Env = append(os.Environ(),
		"API_VERSION="+strings.TrimPrefix(apiTag, "v"),
		"WEB_VERSION="+strings.TrimPrefix(webTag, "v"),
		"CHART_VERSION="+chartSemver,
		"CI_COMPONENTS_VERSION="+strings.TrimPrefix(ciComponentsTag, "v"),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		cl.Fail("bun run generate failed: " + err.Error())
		return fmt.Errorf("bun run generate failed: %w", err)
	}
	cl.Change(fmt.Sprintf(
		"Regenerated Helm chart from schema (chart=%s, api=%s, web=%s, ci-components=%s, kratos=%s)",
		chartSemver, apiTag, webTag, ciComponentsTag, apiTag,
	))
	return nil
}
