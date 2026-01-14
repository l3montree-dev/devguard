package commands

import (
	"fmt"
	"io"
	"net/http"

	"github.com/l3montree-dev/devguard/services"
	"github.com/spf13/cobra"
)

func NewGetCommand() *cobra.Command {
	getCmd := &cobra.Command{
		Use:               "get <url>",
		Args:              cobra.ExactArgs(1),
		Short:             "Do a simple authenticated GET request. Deprecated in favor of 'curl' command.",
		DisableAutoGenTag: true,
		Long: `Perform a simple authenticated GET request signed with a DevGuard Personal Access Token.

This command is deprecated in favor of the more feature-rich 'curl' command but remains
for quick authenticated GET requests. The outgoing HTTP request is signed using the
provided token or the DEVGUARD_TOKEN environment variable.`,
		Example: `  # Simple GET request with token
  devguard-scanner get https://example.com/api/health -t <token>

  # Use environment variable for token
  export DEVGUARD_TOKEN=<your-token>
  devguard-scanner get https://example.com/api/data`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// just use this command to disable the default root persistent pre-run
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := cmd.Flags().GetString("token")
			if err != nil {
				return err
			}

			if token == "" {
				return cmd.Help()
			}
			url := args[0]
			if url == "" {
				return cmd.Help()
			}

			req, err := http.NewRequestWithContext(cmd.Context(), "GET", url, nil)
			if err != nil {
				return err
			}
			err = services.SignRequest(token, req)

			if err != nil {
				return err
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("request failed with status code: %d", resp.StatusCode)
			}

			// just print the body
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			fmt.Print(string(b))
			return nil
		},
	}

	getCmd.Flags().StringP("token", "t", "", "DevGuard Personal Access Token (or set DEVGUARD_TOKEN env var). Used to sign the outgoing request. If empty, command will print help.")

	return getCmd
}
