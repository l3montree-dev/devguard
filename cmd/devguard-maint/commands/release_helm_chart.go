package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	i "github.com/l3montree-dev/devguard/cmd/devguard-maint/internal"
	"github.com/spf13/cobra"
)

var ReleaseHelmChartCmd = &cobra.Command{
	Use:   "helm-chart <tag>",
	Short: "Update the Helm chart, then commit, push, and tag",
	Args:  cobra.ExactArgs(1),
	RunE:  runReleaseHelmChart,
}

func runReleaseHelmChart(_ *cobra.Command, args []string) error {
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

	if err := i.GitCheckoutMain("devguard-helm-chart"); err != nil {
		return fmt.Errorf("checkout main in devguard-helm-chart: %w", err)
	}
	clean, err := i.GitIsClean("devguard-helm-chart")
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory devguard-helm-chart is not clean")
	}

	if err := i.EnsureHelmChangelogEntry(filepath.Join("devguard-helm-chart", "CHANGELOG.md"), tag, apiTag, webTag, ciComponentsTag); err != nil {
		return err
	}

	cl := &i.Changelog{}

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
