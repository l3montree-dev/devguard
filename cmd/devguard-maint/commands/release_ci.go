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

var ReleaseCICmd = &cobra.Command{
	Use:   "ci-components <tag>",
	Short: "Update, tag, and push devguard-ci-component (auto-detects latest scanner version)",
	Args:  cobra.ExactArgs(1),
	RunE:  runReleaseCI,
}

func runReleaseCI(_ *cobra.Command, args []string) error {
	tag := args[0]
	if _, err := i.ValidateTag(tag); err != nil {
		return err
	}
	minor := i.MinorVersion(tag)

	for _, d := range []string{"devguard", "devguard-ci-component"} {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			return fmt.Errorf("directory %q does not exist", d)
		}
	}

	if err := i.CheckChangelogEntry(filepath.Join("devguard-ci-component", "CHANGELOG.md"), tag); err != nil {
		return err
	}

	// Require at least one devguard release with the same minor version to exist.
	scannerTag, err := i.GitLatestTagWithMinor("devguard", minor)
	if err != nil {
		return fmt.Errorf("could not detect latest devguard tag for minor %s: %w", minor, err)
	}
	if scannerTag == "" {
		return fmt.Errorf("no devguard release found with minor version %s — run 'release devguard' first", minor)
	}
	fmt.Printf("✓ Using devguard/scanner tag: %s\n", scannerTag)

	for _, d := range []string{"devguard", "devguard-ci-component"} {
		if err := i.GitCheckoutMain(d); err != nil {
			return fmt.Errorf("checkout main in %s: %w", d, err)
		}
	}

	if err := i.GitPull("devguard-ci-component"); err != nil {
		return fmt.Errorf("pull devguard-ci-component: %w", err)
	}

	clean, err := i.GitIsClean("devguard-ci-component")
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory devguard-ci-component is not clean")
	}

	versionsFile := filepath.Join("devguard-ci-component", "src", "container-image-versions.ts")
	scannerOld := `"ghcr.io/l3montree-dev/devguard/scanner:main"`
	scannerNew := `"ghcr.io/l3montree-dev/devguard/scanner:` + scannerTag + `"`

	changed, err := i.ReplaceInFile(versionsFile, scannerOld, scannerNew)
	if err != nil {
		return fmt.Errorf("update container-image-versions.ts: %w", err)
	}

	cl := &i.Changelog{}
	if changed {
		cl.Change(fmt.Sprintf("Pinned DEVGUARD_SCANNER to %s in container-image-versions.ts", scannerTag))
	} else {
		cl.Fail("DEVGUARD_SCANNER entry not found in container-image-versions.ts — verify the file")
	}

	// Regenerate all templates from the TypeScript source.
	fmt.Println("Regenerating CI component templates...")
	generateCmd := exec.Command("bun", "run", "generate")
	generateCmd.Dir = "devguard-ci-component"
	generateCmd.Stdout = os.Stdout
	generateCmd.Stderr = os.Stderr
	if err := generateCmd.Run(); err != nil {
		return fmt.Errorf("bun run generate failed: %w", err)
	}
	cl.Change("Regenerated CI component templates from TypeScript source")

	cl.PrintSummary("CHANGE SUMMARY - READY FOR APPROVAL")
	if cl.HasErrors() {
		fmt.Println("\nWARNING: Some changes may not have been applied. Review before continuing.")
	}

	if !i.Confirm("\nContinue with tagging?") {
		fmt.Println("Operation cancelled.")
		return nil
	}

	if err := i.GitAdd("devguard-ci-component", "."); err != nil {
		return err
	}
	if err := i.GitCommit("devguard-ci-component", "chore: pin devguard scanner to "+scannerTag); err != nil {
		return err
	}
	cl.Change("Committed pinned scanner version")

	if err := i.GitPush("devguard-ci-component"); err != nil {
		return err
	}
	cl.Change("Pushed devguard-ci-component")

	if err := i.GitTagSigned("devguard-ci-component", tag); err != nil {
		cl.Fail("Failed to tag devguard-ci-component: " + err.Error())
		cl.PrintSummary("FINAL SUMMARY")
		return fmt.Errorf("completed with errors")
	}
	i.GitPushTags("devguard-ci-component")
	cl.Change("Tagged devguard-ci-component with " + tag + " and pushed")

	// Revert scanner back to main in the source and regenerate.
	_, err = i.ReplaceInFile(versionsFile, scannerNew, scannerOld)
	if err != nil {
		return fmt.Errorf("revert container-image-versions.ts: %w", err)
	}

	revertCmd := exec.Command("bun", "run", "generate")
	revertCmd.Dir = "devguard-ci-component"
	revertCmd.Stdout = os.Stdout
	revertCmd.Stderr = os.Stderr
	if err := revertCmd.Run(); err != nil {
		return fmt.Errorf("bun run generate (revert) failed: %w", err)
	}

	if err := i.GitAdd("devguard-ci-component", "."); err != nil {
		return err
	}
	if err := i.GitCommit("devguard-ci-component", "chore: revert scanner to main"); err != nil {
		return err
	}
	if err := i.GitPush("devguard-ci-component"); err != nil {
		return err
	}
	cl.Change("Reverted scanner to main and pushed")

	cl.PrintSummary("FINAL SUMMARY")
	if cl.HasErrors() {
		return fmt.Errorf("completed with errors")
	}
	fmt.Println("\n✓ Script completed successfully!")
	return nil
}

// replaceVersionDefault replaces `default: "from"` with `default: "to"` only
// within blocks that start with a line containing "version:" (flip-flop semantics).
func replaceVersionDefault(path, from, to string) (bool, error) {
	return i.ReplaceLineInFile(path, func() func(string) string {
		inRange := false
		return func(line string) string {
			if strings.Contains(line, "version:") {
				inRange = true
			}
			if inRange {
				if strings.Contains(line, `default: "`+from+`"`) {
					line = strings.Replace(line, `default: "`+from+`"`, `default: "`+to+`"`, 1)
				}
				if strings.Contains(line, "default:") {
					inRange = false
				}
			}
			return line
		}
	}())
}
