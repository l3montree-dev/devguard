package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
)

// minVerifyTag is the earliest release tag checked; images published before
// this version were not built reproducibly across GitHub and GitLab.
const minVerifyTag = "v1.4.0"

// imageRepoPairs lists, for every image DevGuard publishes, the GitHub
// (ghcr.io) and GitLab (registry.opencode.de) repository that build and push
// it independently. Their digests must match bit-for-bit.
var imageRepoPairs = []struct {
	name   string
	ghcr   string
	gitlab string
}{
	{"devguard", "ghcr.io/l3montree-dev/devguard", "registry.opencode.de/oci-community/images/l3montree/devguard/devguard"},
	{"scanner", "ghcr.io/l3montree-dev/devguard/scanner", "registry.opencode.de/oci-community/images/l3montree/devguard/devguard/scanner"},
	{"kratos", "ghcr.io/l3montree-dev/devguard/kratos", "registry.opencode.de/oci-community/images/l3montree/devguard/devguard/kratos"},
	{"postgresql", "ghcr.io/l3montree-dev/devguard/postgresql", "registry.opencode.de/oci-community/images/l3montree/devguard/devguard/postgresql"},
}

// mismatch describes one tag whose digest didn't match (or was missing)
// between the two registries for a given image.
type mismatch struct {
	image  string
	tag    string
	reason string
}

func NewVerifyDigestsCommand() *cobra.Command {
	var (
		tag      string
		wait     time.Duration
		interval time.Duration
	)

	cmd := &cobra.Command{
		Use:   "verify-digests",
		Short: "Verify GitHub and GitLab builds of every DevGuard image are bitwise identical",
		Long: `Compares the manifest digest of the "main" tag and every "v*" tag from
` + minVerifyTag + ` onward between the GitHub Actions (ghcr.io) and GitLab CI
(registry.opencode.de) builds of each DevGuard image (devguard, scanner,
kratos, postgresql).

Images are considered bitwise identical when their digest matches, since the
digest is a content hash of the manifest.

All images/tags are checked concurrently. Only mismatching or missing tags
are printed, as a summary table.

With --tag, only that single tag is checked (instead of the full history),
retrying for up to --wait until the tag has appeared on both registries -
use this to gate a release on its own images matching before publishing.

Requires registry credentials to already be available (e.g. via "docker
login" / a populated docker config) for the GitLab registry.`,
		Example: `  devguard-cli verify-digests
  devguard-cli verify-digests --tag v1.13.1`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if tag != "" {
				return runVerifyDigestsSingleTag(cmd, ctx, tag, wait, interval)
			}
			return runVerifyDigests(cmd, ctx)
		},
	}

	cmd.Flags().StringVar(&tag, "tag", "",
		`check only this single tag (e.g. "v1.13.1") instead of the full "main" + v*
history. Intended for release pipelines gating on the tag being published.`)
	cmd.Flags().DurationVar(&wait, "wait", 30*time.Minute,
		`with --tag, how long to keep retrying while the tag hasn't appeared yet on
both registries (the two release pipelines build independently and race)`)
	cmd.Flags().DurationVar(&interval, "interval", 15*time.Second,
		"with --tag, how long to wait between retries")

	return cmd
}

func runVerifyDigests(cmd *cobra.Command, ctx context.Context) error {
	type imageResult struct {
		image    string
		mismatch []mismatch
		checked  int
		err      error
	}

	results := make([]imageResult, len(imageRepoPairs))
	var wg sync.WaitGroup
	for i, pair := range imageRepoPairs {
		wg.Add(1)
		go func(i int, pair struct {
			name   string
			ghcr   string
			gitlab string
		}) {
			defer wg.Done()
			mismatches, checked, err := verifyImagePair(ctx, pair.name, pair.ghcr, pair.gitlab)
			results[i] = imageResult{image: pair.name, mismatch: mismatches, checked: checked, err: err}
		}(i, pair)
	}
	wg.Wait()

	var all []mismatch
	var totalChecked int
	for _, r := range results {
		if r.err != nil {
			return fmt.Errorf("%s: %w", r.image, r.err)
		}
		totalChecked += r.checked
		all = append(all, r.mismatch...)
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].image != all[j].image {
			return all[i].image < all[j].image
		}
		return all[i].tag < all[j].tag
	})

	if len(all) == 0 {
		fmt.Printf("✓ All %d checked tags are bitwise identical between GitHub and GitLab\n", totalChecked)
		return nil
	}

	fmt.Printf("Checked %d tags, %d mismatched or missing:\n\n", totalChecked, len(all))
	t := table.NewWriter()
	t.SetOutputMirror(cmd.OutOrStdout())
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{"Image", "Tag", "Reason"})
	for _, m := range all {
		t.AppendRow(table.Row{m.image, m.tag, m.reason})
	}
	t.Render()

	return fmt.Errorf("digest verification failed for %d tag(s)", len(all))
}

// verifyImagePair compares digests for the "main" tag and all "v*" tags
// between two repositories publishing the same image. It returns the tags
// that mismatched or were missing, and the total number of tags checked.
func verifyImagePair(ctx context.Context, imageName, repoAName, repoBName string) ([]mismatch, int, error) {
	repoA, err := name.NewRepository(repoAName)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid repository %q: %w", repoAName, err)
	}

	tagsA, err := listTags(ctx, repoA)
	if err != nil {
		return nil, 0, fmt.Errorf("listing tags for %s: %w", repoAName, err)
	}

	relevant := filterRelevantTags(tagsA)
	if len(relevant) == 0 {
		return nil, 0, fmt.Errorf("no matching tags (main or v*) found in %s", repoAName)
	}
	sort.Strings(relevant)

	type tagResult struct {
		tag string
		m   *mismatch
		err error
	}
	tagResults := make([]tagResult, len(relevant))
	var wg sync.WaitGroup
	for i, tag := range relevant {
		wg.Add(1)
		go func(i int, tag string) {
			defer wg.Done()

			digestA, err := digestFor(ctx, repoAName, tag)
			if err != nil {
				tagResults[i] = tagResult{tag: tag, err: fmt.Errorf("fetching digest for %s:%s: %w", repoAName, tag, err)}
				return
			}

			digestB, err := digestFor(ctx, repoBName, tag)
			if err != nil {
				tagResults[i] = tagResult{tag: tag, m: &mismatch{image: imageName, tag: tag, reason: fmt.Sprintf("missing from %s", repoBName)}}
				return
			}

			if digestA != digestB {
				tagResults[i] = tagResult{tag: tag, m: &mismatch{image: imageName, tag: tag, reason: fmt.Sprintf("%s != %s", digestA, digestB)}}
			}
		}(i, tag)
	}
	wg.Wait()

	var mismatches []mismatch
	for _, r := range tagResults {
		if r.err != nil {
			return nil, 0, r.err
		}
		if r.m != nil {
			mismatches = append(mismatches, *r.m)
		}
	}
	return mismatches, len(relevant), nil
}

// runVerifyDigestsSingleTag checks only the given tag across every image,
// retrying while it hasn't yet appeared on both registries - the GitHub and
// GitLab release pipelines build independently and race each other.
func runVerifyDigestsSingleTag(cmd *cobra.Command, ctx context.Context, tag string, wait, interval time.Duration) error {
	type imageResult struct {
		image string
		m     *mismatch
		err   error
	}

	results := make([]imageResult, len(imageRepoPairs))
	var wg sync.WaitGroup
	for i, pair := range imageRepoPairs {
		wg.Add(1)
		go func(i int, pair struct {
			name   string
			ghcr   string
			gitlab string
		}) {
			defer wg.Done()
			m, err := waitForMatchingDigest(ctx, pair.name, pair.ghcr, pair.gitlab, tag, wait, interval)
			results[i] = imageResult{image: pair.name, m: m, err: err}
		}(i, pair)
	}
	wg.Wait()

	var all []mismatch
	for _, r := range results {
		if r.err != nil {
			return fmt.Errorf("%s: %w", r.image, r.err)
		}
		if r.m != nil {
			all = append(all, *r.m)
		}
	}

	if len(all) == 0 {
		fmt.Printf("✓ %s is bitwise identical between GitHub and GitLab for all %d images\n", tag, len(imageRepoPairs))
		return nil
	}

	t := table.NewWriter()
	t.SetOutputMirror(cmd.OutOrStdout())
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{"Image", "Tag", "Reason"})
	for _, m := range all {
		t.AppendRow(table.Row{m.image, m.tag, m.reason})
	}
	t.Render()

	return fmt.Errorf("digest verification failed for tag %s on %d image(s)", tag, len(all))
}

// waitForMatchingDigest polls both registries for tag until it has appeared
// on both and can be compared, or wait elapses - whichever comes first.
func waitForMatchingDigest(ctx context.Context, imageName, repoAName, repoBName, tag string, wait, interval time.Duration) (*mismatch, error) {
	deadline := time.Now().Add(wait)
	for {
		digestA, errA := digestFor(ctx, repoAName, tag)
		digestB, errB := digestFor(ctx, repoBName, tag)

		if errA == nil && errB == nil {
			if digestA == digestB {
				return nil, nil
			}
			return &mismatch{image: imageName, tag: tag, reason: fmt.Sprintf("%s != %s", digestA, digestB)}, nil
		}

		if time.Now().After(deadline) {
			switch {
			case errA != nil && errB != nil:
				return &mismatch{image: imageName, tag: tag, reason: fmt.Sprintf("missing from both registries after %s", wait)}, nil
			case errA != nil:
				return &mismatch{image: imageName, tag: tag, reason: fmt.Sprintf("missing from %s after %s", repoAName, wait)}, nil
			default:
				return &mismatch{image: imageName, tag: tag, reason: fmt.Sprintf("missing from %s after %s", repoBName, wait)}, nil
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func listTags(ctx context.Context, repo name.Repository) ([]string, error) {
	return remote.List(repo, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
}

func digestFor(ctx context.Context, repo, tag string) (string, error) {
	ref, err := name.ParseReference(repo + ":" + tag)
	if err != nil {
		return "", err
	}
	desc, err := remote.Get(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}

func filterRelevantTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if t == "main" {
			out = append(out, t)
			continue
		}
		if !strings.HasPrefix(t, "v") || !semver.IsValid(t) {
			continue
		}
		if semver.Compare(t, minVerifyTag) >= 0 {
			out = append(out, t)
		}
	}
	return out
}
