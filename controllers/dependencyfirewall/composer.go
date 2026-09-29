package dependencyfirewall

import (
	"regexp"
)

const composerMetadataRegistry = "https://repo.packagist.org/p2"

var composerDistHosts = []string{
	"api.github.com", "codeload.github.com",
	"gitlab.com", "bitbucket.org", "repo.packagist.org",
}

var composerProxyPrefixRe = regexp.MustCompile(`^/api/v1/dependency-proxy/(?:[^/]+/)?composer(?:/|$)`)

// ComposerDependencyProxyController handles php dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type ComposerDependencyProxyController struct {
	*DependencyProxyController
}

func NewComposerDependencyProxyController(controller *DependencyProxyController) *ComposerDependencyProxyController {
	return &ComposerDependencyProxyController{DependencyProxyController: controller}
}

type composerEcosystem struct{}

var _ ecosystem = composerEcosystem{}

var composer composerEcosystem
