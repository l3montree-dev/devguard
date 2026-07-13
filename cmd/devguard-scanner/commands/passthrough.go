package commands

import "github.com/spf13/cobra"

// splitPassthroughArgs splits positional args into devguard-scanner's own positional
// arguments and args that should be forwarded verbatim to the underlying scanner
// (trivy, semgrep, checkov, gitleaks), based on a "--" separator, e.g.:
//
//	devguard-scanner sca ./project -- --timeout 10m --skip-dirs vendor
func splitPassthroughArgs(cmd *cobra.Command, args []string) (own []string, passthrough []string) {
	dashIdx := cmd.ArgsLenAtDash()
	if dashIdx < 0 {
		return args, nil
	}
	return args[:dashIdx], args[dashIdx:]
}
