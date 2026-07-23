package commands

import (
	"fmt"
	"os"
	"path/filepath"

	i "github.com/l3montree-dev/devguard/cmd/devguard-maint/internal"
	"github.com/spf13/cobra"
)

var ReleaseK8sIntegrationCmd = &cobra.Command{
	Use:   "k8s-integration <tag>",
	Short: "Tag and push the devguard-k8s-image-inventory repo only",
	Args:  cobra.ExactArgs(1),
	RunE:  runReleaseK8sIntegration,
}

func runReleaseK8sIntegration(_ *cobra.Command, args []string) error {
	tag := args[0]
	if _, err := i.ValidateTag(tag); err != nil {
		return err
	}

	repo := "devguard-k8s-image-inventory"
	if _, err := os.Stat(repo); os.IsNotExist(err) {
		return fmt.Errorf("directory %q does not exist", repo)
	}

	if err := i.CheckChangelogEntry(filepath.Join(repo, "CHANGELOG.md"), tag); err != nil {
		return err
	}

	exists, err := i.GitTagExists(repo, tag)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("tag %s already exists in %s", tag, repo)
	}

	if err := i.GitCheckoutMain(repo); err != nil {
		return fmt.Errorf("checkout main in %s: %w", repo, err)
	}
	clean, err := i.GitIsClean(repo)
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory %s is not clean", repo)
	}

	fmt.Printf("\nTagging %s with %s\n", repo, tag)
	if !i.Confirm("Continue with tagging?") {
		fmt.Println("Operation cancelled.")
		return nil
	}

	cl := &i.Changelog{}

	if err := i.GitTagSigned(repo, tag); err != nil {
		cl.Fail("Failed to tag " + repo + ": " + err.Error())
		cl.PrintSummary("FINAL SUMMARY")
		return fmt.Errorf("completed with errors")
	}
	if err := i.GitPush(repo); err != nil {
		cl.Fail("Failed to push " + repo + ": " + err.Error())
		cl.PrintSummary("FINAL SUMMARY")
		return fmt.Errorf("completed with errors")
	}
	i.GitPushTags(repo)
	cl.Change("Tagged " + repo + " with " + tag + " and pushed")

	cl.PrintSummary("FINAL SUMMARY")
	fmt.Println("\n✓ Script completed successfully!")
	return nil
}
