package commands

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	i "github.com/l3montree-dev/devguard/cmd/devguard-maint/internal"
	"github.com/spf13/cobra"
)

var ReleaseCICmd = &cobra.Command{
	Use:   "ci-components <tag>",
	Short: "Update, tag, and push devguard-ci-component (requires devguard+web already tagged)",
	Args:  cobra.ExactArgs(1),
	RunE:  runReleaseCI,
}

func runReleaseCI(_ *cobra.Command, args []string) error {
	tag := args[0]
	if _, err := i.ValidateTag(tag); err != nil {
		return err
	}

	allDirs := []string{"devguard", "devguard-ci-component", "devguard-web"}
	for _, d := range allDirs {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			return fmt.Errorf("directory %q does not exist", d)
		}
	}

	for _, d := range allDirs {
		if err := i.GitCheckoutMain(d); err != nil {
			return fmt.Errorf("checkout main in %s: %w", d, err)
		}
	}

	for _, d := range []string{"devguard", "devguard-web"} {
		exists, err := i.GitTagExists(d, tag)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("tag %s does not exist in %s — run 'release devguard' first", tag, d)
		}
		fmt.Printf("✓ Tag %s exists in %s\n", tag, d)
	}

	if err := i.GitPull("devguard-ci-component"); err != nil {
		return fmt.Errorf("pull devguard-ci-component: %w", err)
	}

	cl := &i.Changelog{}
	scannerOld := "ghcr.io/l3montree-dev/devguard/scanner:main"
	scannerNew := "ghcr.io/l3montree-dev/devguard/scanner:" + tag

	err := filepath.WalkDir("devguard-ci-component", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yml") {
			return err
		}
		changed, err := i.ReplaceInFile(path, scannerOld, scannerNew)
		if err != nil {
			return err
		}
		if changed {
			cl.Change("Replaced scanner image in " + path)
		}
		if filepath.Base(path) == "full.yml" {
			changed, err = replaceVersionDefault(path, "main", tag)
			if err != nil {
				return err
			}
			if changed {
				cl.Change("Updated version default in " + path)
			} else {
				cl.Fail("No version default changes in " + path)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

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
	if err := i.GitCommit("devguard-ci-component", "chore: updates devguard scanner to "+tag); err != nil {
		return err
	}
	cl.Change("Committed changes in devguard-ci-component")

	if err := i.GitPush("devguard-ci-component"); err != nil {
		return err
	}
	cl.Change("Pushed devguard-ci-component")

	if err := i.GitTagSigned("devguard-ci-component", tag); err != nil {
		cl.Fail("Failed to tag devguard-ci-component: " + err.Error())
	} else {
		i.GitPushTags("devguard-ci-component")
		cl.Change("Tagged devguard-ci-component with " + tag)
	}

	err = filepath.WalkDir("devguard-ci-component", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yml") {
			return err
		}
		changed, err := i.ReplaceInFile(path, scannerNew, scannerOld)
		if err != nil {
			return err
		}
		if changed {
			cl.Change("Reverted scanner image in " + path)
		}
		if filepath.Base(path) == "full.yml" {
			changed, err = replaceVersionDefault(path, tag, "main")
			if err != nil {
				return err
			}
			if changed {
				cl.Change("Reverted version default in " + path)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	if err := i.GitAdd("devguard-ci-component", "."); err != nil {
		return err
	}
	if err := i.GitCommit("devguard-ci-component", "chore: using main devguard scanner"); err != nil {
		return err
	}
	if err := i.GitPush("devguard-ci-component"); err != nil {
		return err
	}
	cl.Change("Committed and pushed revert in devguard-ci-component")

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
