package commands

import (
	"context"
	"fmt"
	"io"
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
	"golang.org/x/sync/errgroup"
)

// minVerifyTag is the earliest release tag checked; images published before
// this version were not built reproducibly across GitHub and GitLab.
const minVerifyTag = "v1.4.0"

// imagePair is, for one image DevGuard publishes, the GitHub (ghcr.io) and
// GitLab (registry.opencode.de) repository that build and push it
// independently under the same tag. Their digests must match bit-for-bit.
type imagePair struct {
	name   string
	ghcr   string
	gitlab string

	// upstreamVersion is the vendored upstream version (e.g. "v26.2.0" for
	// kratos) passed as --upstream-version / upstream_version to
	// generate-tag on both sides (.github/workflows/devguard-scanner.yaml
	// and .gitlab-ci.yml - keep those two values and this one in sync),
	// which prepends it to every tag as "<upstreamVersion>-<ref>". Empty
	// for images with no upstream version (devguard, scanner), whose tag
	// is just the plain ref.
	upstreamVersion string
}

// tagFor returns the tag this pair's image actually carries on both
// registries for the given ref (e.g. "v1.13.1" or "main").
func (p imagePair) tagFor(ref string) string {
	if p.upstreamVersion == "" {
		return ref
	}
	return p.upstreamVersion
}

var imageRepoPairs = []imagePair{
	{name: "devguard", ghcr: "ghcr.io/l3montree-dev/devguard", gitlab: "registry.opencode.de/oci-community/images/l3montree/devguard/devguard"},
	{name: "scanner", ghcr: "ghcr.io/l3montree-dev/devguard/scanner", gitlab: "registry.opencode.de/oci-community/images/l3montree/devguard/devguard/scanner"},
	{name: "kratos", ghcr: "ghcr.io/l3montree-dev/devguard/kratos", gitlab: "registry.opencode.de/oci-community/images/l3montree/devguard/devguard/kratos", upstreamVersion: "v26.2.0"},
	{name: "postgresql", ghcr: "ghcr.io/l3montree-dev/devguard/postgresql", gitlab: "registry.opencode.de/oci-community/images/l3montree/devguard/devguard/postgresql", upstreamVersion: "16.15"},
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
	out := cmd.ErrOrStderr()
	fmt.Fprintf(out, "verifying digests for %d images...\n", len(imageRepoPairs))

	var all []mismatch
	var totalChecked int

	g, ctx := errgroup.WithContext(ctx)
	for _, pair := range imageRepoPairs {
		g.Go(func() error {
			mismatches, checked, err := verifyImagePair(ctx, out, pair)
			if err != nil {
				return fmt.Errorf("%s: %w", pair.name, err)
			}
			fmt.Fprintf(out, "[%s] done: %d tag(s) checked, %d mismatch(es)\n", pair.name, checked, len(mismatches))
			all = append(all, mismatches...)
			totalChecked += checked
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
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
	printMismatchTable(cmd, all)
	return fmt.Errorf("digest verification failed for %d tag(s)", len(all))
}

// verifyImagePair compares digests for the "main" tag and all "v*" tags
// between the two repositories publishing pair's image. It returns the tags
// that mismatched or were missing, and the total number of tags checked.
func verifyImagePair(ctx context.Context, out io.Writer, pair imagePair) ([]mismatch, int, error) {
	repoA, err := name.NewRepository(pair.ghcr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid repository %q: %w", pair.ghcr, err)
	}

	tagsA, err := listTags(ctx, repoA)
	if err != nil {
		return nil, 0, fmt.Errorf("listing tags for %s: %w", pair.ghcr, err)
	}

	relevant := filterRelevantTags(stripUpstreamVersion(tagsA, pair.upstreamVersion))
	if len(relevant) == 0 {
		return nil, 0, fmt.Errorf("no matching tags (main or v*) found in %s", pair.ghcr)
	}
	sort.Strings(relevant)
	fmt.Fprintf(out, "[%s] checking %d tag(s): %s\n", pair.name, len(relevant), strings.Join(relevant, ", "))

	var mismatches []mismatch
	var mu sync.Mutex
	done := 0

	g, ctx := errgroup.WithContext(ctx)
	for _, t := range relevant {
		g.Go(func() error {
			m, err := compareDigest(ctx, pair, t)
			if err != nil {
				return err
			}

			mu.Lock()
			defer mu.Unlock()
			if m != nil {
				mismatches = append(mismatches, *m)
			}
			done++
			fmt.Fprintf(out, "[%s] %d/%d checked (%s)\n", pair.name, done, len(relevant), t)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, 0, err
	}
	return mismatches, len(relevant), nil
}

// compareDigest fetches ref's digest from both registries in pair - via
// pair.tagFor(ref), which accounts for the upstream-version tag prefix - and
// reports a mismatch if it differs or is missing on the GitLab side. An
// error is only returned when the GitHub (reference) side can't be read.
func compareDigest(ctx context.Context, pair imagePair, ref string) (*mismatch, error) {
	tag := pair.tagFor(ref)

	digestA, err := digestFor(ctx, pair.ghcr, tag)
	if err != nil {
		return nil, fmt.Errorf("fetching digest for %s:%s: %w", pair.ghcr, tag, err)
	}

	digestB, err := digestFor(ctx, pair.gitlab, tag)
	if err != nil {
		return &mismatch{image: pair.name, tag: ref, reason: fmt.Sprintf("missing from %s", pair.gitlab)}, nil
	}
	if digestA != digestB {
		return &mismatch{image: pair.name, tag: ref, reason: fmt.Sprintf("%s != %s", digestA, digestB)}, nil
	}
	return nil, nil
}

// runVerifyDigestsSingleTag checks only the given tag across every image,
// retrying while it hasn't yet appeared on both registries - the GitHub and
// GitLab release pipelines build independently and race each other.
func runVerifyDigestsSingleTag(cmd *cobra.Command, ctx context.Context, tag string, wait, interval time.Duration) error {
	out := cmd.ErrOrStderr()
	fmt.Fprintf(out, "verifying tag %s across %d images (waiting up to %s)...\n", tag, len(imageRepoPairs), wait)

	var all []mismatch
	var mu sync.Mutex

	g, ctx := errgroup.WithContext(ctx)
	for _, pair := range imageRepoPairs {
		g.Go(func() error {
			m, err := waitForMatchingDigest(ctx, out, pair, tag, wait, interval)
			if err != nil {
				return fmt.Errorf("%s: %w", pair.name, err)
			}
			switch {
			case m != nil:
				fmt.Fprintf(out, "[%s] mismatch: %s\n", pair.name, m.reason)
				mu.Lock()
				all = append(all, *m)
				mu.Unlock()
			default:
				fmt.Fprintf(out, "[%s] matches\n", pair.name)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	if len(all) == 0 {
		fmt.Printf("✓ %s is bitwise identical between GitHub and GitLab for all %d images\n", tag, len(imageRepoPairs))
		return nil
	}

	printMismatchTable(cmd, all)
	return fmt.Errorf("digest verification failed for tag %s on %d image(s)", tag, len(all))
}

// waitForMatchingDigest polls both registries for ref (via pair.tagFor(ref),
// which accounts for the upstream-version tag prefix) until it has appeared
// on both and can be compared, or wait elapses - whichever comes first.
func waitForMatchingDigest(ctx context.Context, out io.Writer, pair imagePair, ref string, wait, interval time.Duration) (*mismatch, error) {
	tag := pair.tagFor(ref)
	deadline := time.Now().Add(wait)
	for attempt := 1; ; attempt++ {
		digestA, errA := digestFor(ctx, pair.ghcr, tag)
		digestB, errB := digestFor(ctx, pair.gitlab, tag)

		if errA == nil && errB == nil {
			if digestA == digestB {
				return nil, nil
			}
			return &mismatch{image: pair.name, tag: ref, reason: fmt.Sprintf("%s != %s", digestA, digestB)}, nil
		}
		fmt.Fprintf(out, "[%s] attempt %d: tag %s not yet on both registries, retrying...\n", pair.name, attempt, tag)

		if time.Now().After(deadline) {
			switch {
			case errA != nil && errB != nil:
				return &mismatch{image: pair.name, tag: ref, reason: fmt.Sprintf("missing from both registries after %s", wait)}, nil
			case errA != nil:
				return &mismatch{image: pair.name, tag: ref, reason: fmt.Sprintf("missing from %s after %s", pair.ghcr, wait)}, nil
			default:
				return &mismatch{image: pair.name, tag: ref, reason: fmt.Sprintf("missing from %s after %s", pair.gitlab, wait)}, nil
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func printMismatchTable(cmd *cobra.Command, mismatches []mismatch) {
	t := table.NewWriter()
	t.SetOutputMirror(cmd.OutOrStdout())
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{"Image", "Tag", "Reason"})
	for _, m := range mismatches {
		t.AppendRow(table.Row{m.image, m.tag, m.reason})
	}
	t.Render()
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

// stripUpstreamVersion strips the "<upstreamVersion>-" prefix from each tag
// that carries it, discarding tags that don't (a leftover from before the
// upstream version was added, or unrelated tags). A no-op when
// upstreamVersion is empty.
func stripUpstreamVersion(tags []string, upstreamVersion string) []string {
	if upstreamVersion == "" {
		return tags
	}
	prefix := upstreamVersion + "-"
	var out []string
	for _, t := range tags {
		if ref, ok := strings.CutPrefix(t, prefix); ok {
			out = append(out, ref)
		}
	}
	return out
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
