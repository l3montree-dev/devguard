package normalize

import "net/url"

// ArtifactName canonicalizes an artifact name by url-decoding it exactly
// once. Artifact names are looked up via a url-decoded path parameter (see
// shared.GetArtifactName), so a name that is stored without going through
// the same decoding step can end up indistinguishable, once placed in a
// URL, from a different, already-existing artifact whose name happens to
// decode to the same value. Applying this at every write site guarantees
// there is exactly one canonical stored form per artifact.
//
// If the name is not validly percent-encoded, it is returned unchanged.
func ArtifactName(name string) string {
	decoded, err := url.PathUnescape(name)
	if err != nil {
		return name
	}
	return decoded
}
