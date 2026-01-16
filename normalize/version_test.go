package normalize_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"golang.org/x/mod/semver"
)

func TestConvertToSemver(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		semver, err := normalize.ConvertToSemver("")
		assert.NoError(t, err)
		assert.Equal(t, "", semver)
	})

	t.Run("redheat versions", func(t *testing.T) {
		semver, err := normalize.ConvertToSemver("31.4.0-1.el5_11")
		assert.NoError(t, err)
		assert.Equal(t, "31.4.0-1.el5.11", semver)
	})

	t.Run("valid semver", func(t *testing.T) {
		semver, err := normalize.ConvertToSemver("1.2.3")
		assert.NoError(t, err)
		assert.Equal(t, "1.2.3", semver)
	})

	t.Run("with epoch", func(t *testing.T) {
		semver, err := normalize.ConvertToSemver("2:1.2.3")
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

func TestConvertToSemverVariousFormats(t *testing.T) {
	//this is important for introducing semver sorting
	t.Run("zero version", func(t *testing.T) {
		result, err := normalize.ConvertToSemver("0")
		assert.NoError(t, err)
		assert.Equal(t, "0.0.0", result)
	})
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
		assert.Equal(t, "5.14.0-284.11.1.el9.2", result)
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

func TestCheckVersion(t *testing.T) {
	t.Run("unsupported package type", func(t *testing.T) {
		result, err := normalize.CheckVersion(nil, nil, nil, "1.2.3", "unsupported")
		assert.Error(t, err)
		assert.False(t, result)
		assert.Contains(t, err.Error(), "unsupported affected component type")
	})

	t.Run("error handling", func(t *testing.T) {
		t.Run("deb - empty target version", func(t *testing.T) {
			result, err := normalize.CheckVersion(nil, nil, nil, "", "deb")
			assert.Error(t, err)
			assert.False(t, result)
		})

		t.Run("deb - malformed target version", func(t *testing.T) {
			result, err := normalize.CheckVersion(nil, nil, nil, "not-a-valid-version!", "deb")
			assert.Error(t, err)
			assert.False(t, result)
		})

		t.Run("deb - malformed exact version", func(t *testing.T) {
			version := "invalid!@#"
			result, err := normalize.CheckVersion(&version, nil, nil, "1.2.3", "deb")
			assert.Error(t, err)
			assert.False(t, result)
		})

		t.Run("deb - malformed introduced version", func(t *testing.T) {
			introduced := "bad-version!!"
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "1.5.0", "deb")
			assert.Error(t, err)
			assert.False(t, result)
		})

		t.Run("deb - malformed fixed version", func(t *testing.T) {
			introduced := "1.0.0"
			fixed := "invalid@@"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "1.5.0", "deb")
			assert.Error(t, err)
			assert.False(t, result)
		})

		t.Run("apk - malformed exact version", func(t *testing.T) {
			version := "not@valid"
			result, err := normalize.CheckVersion(&version, nil, nil, "1.2.3", "apk")
			assert.Error(t, err)
			assert.False(t, result)
		})

		t.Run("apk - malformed introduced version", func(t *testing.T) {
			introduced := "bad!version"
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "1.5.0", "apk")
			assert.Error(t, err)
			assert.False(t, result)
		})

		t.Run("apk - malformed fixed version", func(t *testing.T) {
			introduced := "1.0.0"
			fixed := "invalid@@version"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "1.5.0", "apk")
			assert.Error(t, err)
			assert.False(t, result)
		})
		t.Run("apk - should work with empty introduced version", func(t *testing.T) {
			result, err := normalize.CheckVersion(nil, nil, utils.Ptr("2.0.0"), "1.5.0", "apk")
			assert.NoError(t, err)
			assert.True(t, result)
		})
		t.Run("apk - should work with empty fixed version", func(t *testing.T) {
			result, err := normalize.CheckVersion(nil, utils.Ptr("1.0.0"), nil, "1.5.0", "apk")
			assert.NoError(t, err)
			assert.True(t, result)
		})
	})

	t.Run("deb package type", func(t *testing.T) {
		t.Run("exact version match", func(t *testing.T) {
			version := "1.2.3-1"
			result, err := normalize.CheckVersion(&version, nil, nil, "1.2.3-1", "deb")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("should work with curl version", func(t *testing.T) {
			lookingForVersion := "7.88.1-10+deb12u12"

			result, err := normalize.CheckVersion(nil, nil, utils.Ptr("7.88.1-10+deb12u1"), lookingForVersion, "deb")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("exact version no match", func(t *testing.T) {
			version := "1.2.3-1"
			result, err := normalize.CheckVersion(&version, nil, nil, "1.2.3-2", "deb")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("target between introduced and fixed", func(t *testing.T) {
			introduced := "1.0.0"
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "1.5.0", "deb")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("target equals introduced", func(t *testing.T) {
			introduced := "1.0.0"
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "1.0.0", "deb")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("target equals fixed", func(t *testing.T) {
			introduced := "1.0.0"
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "2.0.0", "deb")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("target below introduced", func(t *testing.T) {
			introduced := "1.0.0"
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "0.9.0", "deb")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("target above fixed", func(t *testing.T) {
			introduced := "1.0.0"
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "2.1.0", "deb")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("only introduced provided - target greater", func(t *testing.T) {
			introduced := "1.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, nil, "1.5.0", "deb")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("only introduced provided - target smaller", func(t *testing.T) {
			introduced := "1.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, nil, "0.9.0", "deb")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("only fixed provided - target less", func(t *testing.T) {
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, nil, &fixed, "1.5.0", "deb")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("only fixed provided - target greater", func(t *testing.T) {
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, nil, &fixed, "2.1.0", "deb")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("complex debian versions", func(t *testing.T) {
			introduced := "2.4.37-5.el8"
			fixed := "2.4.37-10.el8"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "2.4.37-7.el8", "deb")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("should work with empty introduced version", func(t *testing.T) {
			result, err := normalize.CheckVersion(nil, nil, utils.Ptr("2.0.0"), "1.5.0", "deb")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("should work with empty fixed version", func(t *testing.T) {
			result, err := normalize.CheckVersion(nil, utils.Ptr("1.0.0"), nil, "1.5.0", "deb")
			assert.NoError(t, err)
			assert.True(t, result)
		})
	})

	t.Run("rpm package type", func(t *testing.T) {
		t.Run("exact version match", func(t *testing.T) {
			version := "1.2.3-1.el9"
			result, err := normalize.CheckVersion(&version, nil, nil, "1.2.3-1.el9", "rpm")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("target between introduced and fixed", func(t *testing.T) {
			introduced := "1.0.0-1.el9"
			fixed := "2.0.0-1.el9"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "1.5.0-1.el9", "rpm")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("target below introduced", func(t *testing.T) {
			introduced := "1.0.0"
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "0.9.0", "rpm")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("target above fixed", func(t *testing.T) {
			introduced := "1.0.0"
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "2.1.0", "rpm")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("only introduced provided", func(t *testing.T) {
			introduced := "1.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, nil, "1.5.0", "rpm")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("only fixed provided", func(t *testing.T) {
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, nil, &fixed, "1.5.0", "rpm")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("rpm with epoch", func(t *testing.T) {
			introduced := "0:1.2.3-1.el9"
			fixed := "0:1.2.3-10.el9"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "0:1.2.3-5.el9", "rpm")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("should work with empty introduced version", func(t *testing.T) {
			result, err := normalize.CheckVersion(nil, nil, utils.Ptr("2.0.0"), "1.5.0", "rpm")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("should work with empty fixed version", func(t *testing.T) {
			result, err := normalize.CheckVersion(nil, utils.Ptr("1.0.0"), nil, "1.5.0", "rpm")
			assert.NoError(t, err)
			assert.True(t, result)
		})
	})

	t.Run("apk package type", func(t *testing.T) {
		t.Run("exact version match", func(t *testing.T) {
			version := "1.2.3-r0"
			result, err := normalize.CheckVersion(&version, nil, nil, "1.2.3-r0", "apk")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("target between introduced and fixed", func(t *testing.T) {
			introduced := "1.0.0-r0"
			fixed := "2.0.0-r0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "1.5.0-r0", "apk")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("target below introduced", func(t *testing.T) {
			introduced := "1.0.0"
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "0.9.0", "apk")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("target above fixed", func(t *testing.T) {
			introduced := "1.0.0"
			fixed := "2.0.0"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "2.1.0", "apk")
			assert.NoError(t, err)
			assert.False(t, result)
		})

		t.Run("only introduced provided", func(t *testing.T) {
			introduced := "1.0.0-r0"
			result, err := normalize.CheckVersion(nil, &introduced, nil, "1.5.0-r0", "apk")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("only fixed provided", func(t *testing.T) {
			fixed := "2.0.0-r0"
			result, err := normalize.CheckVersion(nil, nil, &fixed, "1.5.0-r0", "apk")
			assert.NoError(t, err)
			assert.True(t, result)
		})

		t.Run("apk revision numbers", func(t *testing.T) {
			introduced := "1.2.3-r5"
			fixed := "1.2.3-r10"
			result, err := normalize.CheckVersion(nil, &introduced, &fixed, "1.2.3-r7", "apk")
			assert.NoError(t, err)
			assert.True(t, result)
		})
	})
}
