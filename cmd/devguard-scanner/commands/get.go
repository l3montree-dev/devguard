package commands

import (
	"fmt"
	"io"
	"net/http"

	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/spf13/cobra"
)

func NewGetCommand() *cobra.Command {
	getCmd := &cobra.Command{
		Use:   "get",
		Args:  cobra.ExactArgs(1),
		Short: "Do a simple authenticated GET request",
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
			err = pat.SignRequest(token, req)

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

	getCmd.Flags().StringP("token", "t", "", "Token")

	return getCmd
}
