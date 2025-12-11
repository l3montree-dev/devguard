package normalize_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/stretchr/testify/assert"
	"golang.org/x/mod/semver"
)

func TestConvertToSemver(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		semver, err := normalize.ConvertToSemver("")
		assert.NoError(t, err)
		assert.Equal(t, "", semver)
	})

	t.Run("valid semver", func(t *testing.T) {
		semver, err := normalize.ConvertToSemver("1.2.3")
		assert.NoError(t, err)
		assert.Equal(t, "1.2.3", semver)
	})

	t.Run("valid semver with pre-release", func(t *testing.T) {
		smallSemver, err := normalize.ConvertToSemver("1.2.3-rc1")
		assert.NoError(t, err)
		biggerSemver, err := normalize.ConvertToSemver("1.2.3-rc2")
		assert.NoError(t, err)
		assert.True(t, semver.Compare("v"+smallSemver, "v"+biggerSemver) < 0)
	})

	t.Run("valid semver with build metadata", func(t *testing.T) {
		smallSemver, err := normalize.ConvertToSemver("1.2.3+build1")
		assert.NoError(t, err)
		biggerSemver, err := normalize.ConvertToSemver("1.2.4")
		assert.NoError(t, err)
		assert.True(t, semver.Compare("v"+smallSemver, "v"+biggerSemver) < 0)
	})

	// pre-release should be smaller than release
	t.Run("pre-release should be smaller than release", func(t *testing.T) {
		s, err := normalize.ConvertToSemver("1.2.3-rc1")
		assert.NoError(t, err)
		assert.True(t, semver.Compare("v1.2.3", "v"+s) > 0)
	})
}

func TestConvertRPMtoSemVer(t *testing.T) {
	t.Run("simple version without release", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("1.2.3")
		assert.NoError(t, err)
		assert.Equal(t, "1.2.3", result)
	})

	t.Run("version with release number", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("1.2.3-5")
		assert.NoError(t, err)
		assert.Equal(t, "1.2.3-5", result)
	})

	t.Run("version with epoch", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("2:1.2.3-5")
		assert.NoError(t, err)
		assert.Equal(t, "1.2.3-5", result)
	})

	t.Run("version with epoch and complex release", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("1:1.2.3-5.el9")
		assert.NoError(t, err)
		assert.Equal(t, "1.2.3-5.el9", result)
	})

	t.Run("version with distro tag in release", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("2.4.37-5.el8")
		assert.NoError(t, err)
		assert.Equal(t, "2.4.37-5.el8", result)
	})

	t.Run("version with two segments only", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("1.2-10")
		assert.NoError(t, err)
		assert.Equal(t, "1.2.0-10", result)
	})

	t.Run("version with one segment only", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("5-0-3.el9")
		assert.NoError(t, err)
		assert.Equal(t, "5.0.0-0-3.el9", result)
	})

	t.Run("version with special characters", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("1.2.3~rc1-5")
		assert.NoError(t, err)
		assert.Equal(t, "1.2.3-rc1-5", result)
	})

	t.Run("version with underscores", func(t *testing.T) {
		_, err := normalize.ConvertToSemver("1_2_3-10.fc38")
		assert.Error(t, err)

	})

	t.Run("version with multiple dots", func(t *testing.T) {
		_, err := normalize.ConvertToSemver("1.2.3.4.5-7")
		assert.Error(t, err)
	})

	t.Run("version with letters in version part", func(t *testing.T) {
		_, err := normalize.ConvertToSemver("1.2.3a-5")
		assert.Error(t, err)
	})

	t.Run("complex real-world example - httpd", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("2.4.57-5.el9")
		assert.NoError(t, err)
		assert.Equal(t, "2.4.57-5.el9", result)
	})

	t.Run("complex real-world example - kernel", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("5.14.0-284.11.1.el9_2")
		assert.NoError(t, err)
		assert.Equal(t, "5.14.0-284.11.1.el9_2", result)
	})

	t.Run("version with only release number", func(t *testing.T) {

		_, err := normalize.ConvertToSemver("15.fc39")
		assert.Error(t, err)
	})

	t.Run("version with no numeric release", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("1.2.3-beta")
		assert.NoError(t, err)
		assert.Equal(t, "1.2.3-beta", result)
	})

	t.Run("complex version with letters and epoch", func(t *testing.T) {
		_, err := normalize.ConvertToSemver("0:B.02.16-4.el6cf")
		assert.Error(t, err)
	})

	t.Run("version with multiple hyphens", func(t *testing.T) {
		_, err := normalize.ConvertToSemver("2024.2.69_v8.0.303-91.4.el9_4")
		assert.Error(t, err)
	})
}
