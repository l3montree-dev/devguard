package repositories

import (
	"regexp"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// likeAny mirrors `ecosystem LIKE ANY (patterns)`
func likeAny(patterns []string, ecosystem string) bool {
	for _, pattern := range patterns {
		expression := regexp.QuoteMeta(pattern)
		expression = strings.ReplaceAll(expression, "%", ".*")
		expression = strings.ReplaceAll(expression, "_", ".")
		if regexp.MustCompile("^" + expression + "$").MatchString(ecosystem) {
			return true
		}
	}
	return false
}

func redHatPatterns(t *testing.T, purl string) []string {
	t.Helper()
	parsed, err := packageurl.FromString(purl)
	require.NoError(t, err)
	matchCtx := normalize.ParsePurlForMatching(parsed)
	return QualifierEcosystemPattern(matchCtx.Qualifiers, matchCtx.Namespace, matchCtx.OriginalVersion)
}

func TestRedHatEcosystemPatterns(t *testing.T) {
	rhel9 := []string{
		"Red Hat:enterprise_linux:9::baseos",
		"Red Hat:enterprise_linux:9::appstream",
		"Red Hat:rhel_eus:9.4::appstream",
		"Red Hat:rhel_e4s:9.0::baseos",
	}
	layered9 := []string{
		"Red Hat:satellite:6.16::el9",
		"Red Hat:satellite_capsule:6.16::el9",
		"Red Hat:ansible_automation_platform:2.4::el9",
		"Red Hat:openshift:4.14::el9",
		"Red Hat:openshift_ironic:4.14::el9",
	}
	otherMajors := []string{
		"Red Hat:enterprise_linux:8::appstream",
		"Red Hat:enterprise_linux:10.2",
		"Red Hat:openstack:9::el7",
		"Red Hat:certificate_system:9.7::el7",
		"Red Hat:ceph_storage:9.0::el10",
	}

	tests := []struct {
		name         string
		purl         string
		matchLayered bool
	}{
		{"a RHEL build", "pkg:rpm/redhat/libcomps@0.1.18-1.el9?arch=x86_64&distro=redhat-9.8", false},
		{"a RHEL build with a minor dist tag", "pkg:rpm/redhat/glibc@2.34-284.el9_8.4?arch=x86_64&distro=redhat-9.8", false},
		{"a RHEL module build", "pkg:rpm/redhat/nodejs@24.19.0-1.module%2Bel9.8.0%2B24428%2B77f1d00a?arch=x86_64&distro=redhat-9.8&epoch=1", false},
		{"a Satellite build", "pkg:rpm/redhat/libcomps@0.1.21-1.el9pc?arch=x86_64&distro=redhat-9.8", true},
		{"an Ansible Automation Platform build", "pkg:rpm/redhat/python3-urllib3@1.26.20-1.el9ap?arch=noarch&distro=redhat-9.8", true},
		{"an OpenShift build", "pkg:rpm/redhat/python3-decorator@4.4.2-6.rhaos4.14.el9?arch=noarch&distro=redhat-9.8", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := redHatPatterns(t, tt.purl)
			for _, ecosystem := range rhel9 {
				assert.True(t, likeAny(patterns, ecosystem), "expected %q to match", ecosystem)
			}
			for _, ecosystem := range layered9 {
				assert.Equal(t, tt.matchLayered, likeAny(patterns, ecosystem), "layered product %q", ecosystem)
			}
			for _, ecosystem := range otherMajors {
				assert.False(t, likeAny(patterns, ecosystem), "expected %q not to match", ecosystem)
			}
		})
	}

	t.Run("RHEL 10 reaches its unified minor versioning", func(t *testing.T) {
		patterns := redHatPatterns(t, "pkg:rpm/redhat/glibc@2.39-145.el10_2?arch=x86_64&distro=redhat-10.2")
		assert.True(t, likeAny(patterns, "Red Hat:enterprise_linux:10.2"))
		assert.True(t, likeAny(patterns, "Red Hat:enterprise_linux:10::baseos"))
		assert.False(t, likeAny(patterns, "Red Hat:enterprise_linux:9::baseos"))
		assert.False(t, likeAny(patterns, "Red Hat:ceph_storage:9.0::el10"))
	})

	t.Run("a layered product with the major in another field position", func(t *testing.T) {
		patterns := redHatPatterns(t, "pkg:rpm/redhat/qpid-cpp@1.36.0-1.el6mrg?arch=x86_64&distro=redhat-6.10")
		assert.True(t, likeAny(patterns, "Red Hat:enterprise_mrg:2:server:el6"))
	})

	t.Run("no distro, no patterns", func(t *testing.T) {
		assert.Nil(t, redHatPatterns(t, "pkg:rpm/redhat/libcomps@0.1.18-1.el9?arch=x86_64"))
	})
}
