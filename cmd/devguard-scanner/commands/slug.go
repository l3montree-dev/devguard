package commands

import (
	"fmt"

	"github.com/gosimple/slug"
	"github.com/spf13/cobra"
)

func NewSlugCommand() *cobra.Command {
	slugCmd := &cobra.Command{
		Use:               "slug <text>",
		Args:              cobra.ExactArgs(1),
		Short:             "Create a URL-friendly slug from text",
		DisableAutoGenTag: true,
		Long: `Create a URL-friendly slug from the provided text.

Useful for generating artifact names or identifiers. The slug is printed to stdout.`,
		Example: `  # Generate a slug from text
  devguard-scanner slug "My Project Name"

  # Use in shell script
  SLUG=$(devguard-scanner slug "My App v1.2.3")`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// just use this command to disable the default root persistent pre-run
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return fmt.Errorf("too many arguments, only one argument is needed, that being the text to slugify")
			}
			slugifiedText := slug.Make(args[0])

			fmt.Print(string(slugifiedText))
			return nil
		},
	}

	return slugCmd
}
