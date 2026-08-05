package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	i "github.com/l3montree-dev/devguard/cmd/devguard-maint/internal"
	"github.com/spf13/cobra"
)

var ReleaseWebCmd = &cobra.Command{
	Use:   "web <tag>",
	Short: "Bump package.json, tag, and push devguard-web only",
	Args:  cobra.ExactArgs(1),
	RunE:  runReleaseWeb,
}

func runReleaseWeb(_ *cobra.Command, args []string) error {
	tag := args[0]
	semver, err := i.ValidateTag(tag)
	if err != nil {
		return err
	}

	for _, d := range []string{"devguard-web", "devguard"} {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			return fmt.Errorf("directory %q does not exist", d)
		}
	}

	if err := i.CheckChangelogEntry(filepath.Join("devguard-web", "CHANGELOG.md"), tag); err != nil {
		return err
	}

	exists, err := i.GitTagExists("devguard-web", tag)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("tag %s already exists in devguard-web", tag)
	}

	if err := i.GitCheckoutMain("devguard-web"); err != nil {
		return fmt.Errorf("checkout main in devguard-web: %w", err)
	}
	clean, err := i.GitIsClean("devguard-web")
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory devguard-web is not clean")
	}

	cl := &i.Changelog{}

	if i.Confirm("Run e2e tests now? They regenerate the docs screenshots in e2e/docs-screenshots.") {
		if err := runWebE2ETests(); err != nil {
			return fmt.Errorf("e2e tests failed: %w", err)
		}
		cl.Change("Ran e2e tests and regenerated docs screenshots")
	} else {
		fmt.Println("Skipping e2e tests — docs screenshots will not be refreshed")
	}

	pkgJSON := filepath.Join("devguard-web", "package.json")
	versionRe := regexp.MustCompile(`"version":\s*"[^"]*"`)
	data, err := os.ReadFile(pkgJSON)
	if err != nil {
		return fmt.Errorf("read %s: %w", pkgJSON, err)
	}
	bumped := versionRe.ReplaceAll(data, []byte(`"version": "`+semver+`"`))
	if err := os.WriteFile(pkgJSON, bumped, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", pkgJSON, err)
	}

	fmt.Printf("\npackage.json bumped to %s (uncommitted — will commit on confirm)\n", semver)
	fmt.Printf("Tag: %s → devguard-web\n\n", tag)

	if !i.Confirm("Continue with tagging?") {
		_ = i.GitRun("devguard-web", "checkout", "--", "package.json")
		_ = i.GitRun("devguard-web", "checkout", "--", "e2e/docs-screenshots")
		fmt.Println("Operation cancelled.")
		return nil
	}

	if err := i.GitAdd("devguard-web", "package.json", "e2e/docs-screenshots"); err != nil {
		return err
	}
	if err := i.GitCommit("devguard-web", "chore: bump version to "+semver); err != nil {
		return err
	}
	cl.Change("Committed devguard-web/package.json version bump to " + semver)

	if err := i.GitTagSigned("devguard-web", tag); err != nil {
		cl.Fail("Failed to tag devguard-web: " + err.Error())
		cl.PrintSummary("FINAL SUMMARY")
		return fmt.Errorf("completed with errors")
	}
	if err := i.GitPush("devguard-web"); err != nil {
		cl.Fail("Failed to push devguard-web: " + err.Error())
		cl.PrintSummary("FINAL SUMMARY")
		return fmt.Errorf("completed with errors")
	}
	i.GitPushTags("devguard-web")
	cl.Change("Tagged devguard-web with " + tag + " and pushed")

	cl.PrintSummary("FINAL SUMMARY")
	fmt.Println("\n✓ Script completed successfully!")
	return nil
}

// runWebE2ETests runs the DevGuard e2e suite (`npm run e2e`) from the
// devguard-web repo root. The suite requires e2e/.env to be configured
// (DEVGUARD_DOMAIN and friends — see e2e/README.md) and hits a live
// DevGuard instance; it also regenerates the screenshots checked into
// e2e/docs-screenshots.
func runWebE2ETests() error {
	cmd := exec.Command("npm", "run", "e2e")
	cmd.Dir = "devguard-web"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
