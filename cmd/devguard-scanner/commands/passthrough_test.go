package commands

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestSplitPassthroughArgs(t *testing.T) {
	newCmd := func() *cobra.Command {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("path", ".", "")
		return cmd
	}

	t.Run("no dash separator forwards nothing", func(t *testing.T) {
		cmd := newCmd()
		err := cmd.ParseFlags([]string{"./my-repo"})
		assert.NoError(t, err)

		own, passthrough := splitPassthroughArgs(cmd, cmd.Flags().Args())
		assert.Equal(t, []string{"./my-repo"}, own)
		assert.Nil(t, passthrough)
	})

	t.Run("args after -- are forwarded and stripped from own args", func(t *testing.T) {
		cmd := newCmd()
		err := cmd.ParseFlags([]string{"./my-repo", "--", "--timeout", "10m", "--skip-dirs", "vendor"})
		assert.NoError(t, err)

		own, passthrough := splitPassthroughArgs(cmd, cmd.Flags().Args())
		assert.Equal(t, []string{"./my-repo"}, own)
		assert.Equal(t, []string{"--timeout", "10m", "--skip-dirs", "vendor"}, passthrough)
	})

	t.Run("bare -- with no own args and only passthrough args", func(t *testing.T) {
		cmd := newCmd()
		err := cmd.ParseFlags([]string{"--", "--severity", "HIGH"})
		assert.NoError(t, err)

		own, passthrough := splitPassthroughArgs(cmd, cmd.Flags().Args())
		assert.Equal(t, []string{}, own)
		assert.Equal(t, []string{"--severity", "HIGH"}, passthrough)
	})
}
