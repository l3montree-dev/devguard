package commands

import (
	"fmt"
	"os"
	"path/filepath"

	i "github.com/l3montree-dev/devguard/cmd/devguard-maint/internal"
	"github.com/spf13/cobra"
)

var ReleaseDevguardCmd = &cobra.Command{
	Use:   "devguard <tag>",
	Short: "Tag and push the devguard backend only",
	Args:  cobra.ExactArgs(1),
	RunE:  runReleaseDevguard,
}

func runReleaseDevguard(_ *cobra.Command, args []string) error {
	tag := args[0]
	if _, err := i.ValidateTag(tag); err != nil {
		return err
	}

	if _, err := os.Stat("devguard"); os.IsNotExist(err) {
		return fmt.Errorf("directory %q does not exist", "devguard")
	}

	if err := i.CheckChangelogEntry(filepath.Join("devguard", "CHANGELOG.md"), tag); err != nil {
		return err
	}

	exists, err := i.GitTagExists("devguard", tag)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("tag %s already exists in devguard", tag)
	}

	if err := i.GitCheckoutMain("devguard"); err != nil {
		return fmt.Errorf("checkout main in devguard: %w", err)
	}
	clean, err := i.GitIsClean("devguard")
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory devguard is not clean")
	}

	fmt.Printf("\nTagging devguard with %s\n", tag)
	if !i.Confirm("Continue with tagging?") {
		fmt.Println("Operation cancelled.")
		return nil
	}

	cl := &i.Changelog{}

	if err := i.GitTagSigned("devguard", tag); err != nil {
		cl.Fail("Failed to tag devguard: " + err.Error())
		cl.PrintSummary("FINAL SUMMARY")
		return fmt.Errorf("completed with errors")
	}
	if err := i.GitPush("devguard"); err != nil {
		cl.Fail("Failed to push devguard: " + err.Error())
		cl.PrintSummary("FINAL SUMMARY")
		return fmt.Errorf("completed with errors")
	}
	i.GitPushTags("devguard")
	cl.Change("Tagged devguard with " + tag + " and pushed")

	cl.PrintSummary("FINAL SUMMARY")
	fmt.Println("\n✓ Script completed successfully!")
	fmt.Printf("\nTo release the web frontend at the same tag, run:\n  devguard-maint release web %s\n", tag)
	return nil
}
