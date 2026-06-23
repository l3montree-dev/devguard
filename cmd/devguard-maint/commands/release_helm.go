package commands

import (
	"fmt"
	"os"
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

	required := []string{
		"devguard",
		"devguard/docker-compose-try-it.yaml",
		"devguard-helm-chart/Chart.yaml",
	}
	for _, path := range required {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("%q does not exist", path)
		}
	}

	if err := i.GitCheckoutMain("devguard"); err != nil {
		return err
	}
	clean, err := i.GitIsClean("devguard")
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory devguard is not clean")
	}

	cl := &i.Changelog{}

	if err := updateDockerCompose(tag, cl); err != nil {
		return err
	}
	if err := updateHelmChart(tag, semver, cl); err != nil {
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
	if err := i.GitCommit("devguard", "chore: update docker-compose-try-it.yaml to "+tag); err != nil {
		return err
	}
	if err := i.GitPush("devguard"); err != nil {
		return err
	}
	cl.Change("Committed and pushed docker-compose-try-it.yaml")

	helmMsg := fmt.Sprintf("chore: update Helm chart to %s\n\n- Updated devguard image to %s\n- Updated devguard-web image to %s\n- Updated devguard-postgresql image to %s\n- Updated Helm chart version to %s, appVersion to %s",
		tag, tag, tag, tag, semver, tag)
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

func updateDockerCompose(tag string, cl *i.Changelog) error {
	path := "devguard/docker-compose-try-it.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	images := []string{
		"ghcr.io/l3montree-dev/devguard:",
		"ghcr.io/l3montree-dev/devguard-web:",
		"ghcr.io/l3montree-dev/devguard/postgresql:",
	}
	imageTagRe := regexp.MustCompile(`(ghcr\.io/l3montree-dev/devguard(?:-web|/postgresql)?:)[^\s"]+`)
	updated := imageTagRe.ReplaceAllStringFunc(string(data), func(m string) string {
		for _, prefix := range images {
			if strings.HasPrefix(m, prefix) {
				return prefix + tag
			}
		}
		return m
	})

	if updated == string(data) {
		cl.Fail("No changes in docker-compose-try-it.yaml — verify image patterns")
		return nil
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return err
	}
	cl.Change("Updated docker-compose-try-it.yaml to " + tag)
	return nil
}

func updateHelmChart(tag, semver string, cl *i.Changelog) error {
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

	inDevguardImage := false
	_, err = i.ReplaceLineInFile(valuesPath, func(line string) string {
		if strings.Contains(line, "repository:") {
			inDevguardImage = strings.Contains(line, "ghcr.io/l3montree-dev/")
		}
		if inDevguardImage && regexp.MustCompile(`^\s+tag:\s`).MatchString(line) {
			return regexp.MustCompile(`tag:.*`).ReplaceAllString(line, "tag: "+tag)
		}
		return line
	})
	if err != nil {
		return err
	}
	cl.Change("Updated values.yaml image tags to " + tag)

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
