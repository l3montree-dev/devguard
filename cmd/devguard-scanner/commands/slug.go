package commands

import (
	"fmt"

	"github.com/gosimple/slug"
	"github.com/spf13/cobra"
)

func NewSlugCommand() *cobra.Command {
	slugCmd := &cobra.Command{
		Use:   "slug",
		Args:  cobra.ExactArgs(1),
		Short: "Get the slug of a version using the slug method from the github package ",
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
