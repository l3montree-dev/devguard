// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dependencyfirewall

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

const (
	alpineIndexTTL      = 30 * time.Minute
	alpineIndexMaxBytes = 256 << 20
	// the main x86_64 APKINDEX is a few MB
	alpineIndexFileMaxBytes = 64 << 20
)

type alpineIndex struct {
	archive []byte
	size    int
}

// upstream index of one registry directory, shared by all secrets - only filtering and signing is per secret
type alpineUpstreamIndex struct {
	entries    []tarEntry
	apkIndex   int // position of the APKINDEX entry
	buildTimes map[string]time.Time
	verified   bool
	size       int
}

func (d *AlpineDependencyProxyController) getAlpineIndex(ctx context.Context, configs DependencyProxyConfigs, dir string) (*alpineIndex, error) {
	key := configs.Secret.String() + "/" + configs.getRegistry(alpine, alpineRegistry) + "/" + dir
	return d.alpineIndexes.GetOrLoad(key, func() (*alpineIndex, error) {
		return d.loadAlpineIndex(context.WithoutCancel(ctx), configs, dir)
	})
}

func (d *AlpineDependencyProxyController) getAlpineUpstreamIndex(ctx context.Context, registryConfig dtos.AlpineRegistryConfig, dir string) (*alpineUpstreamIndex, error) {
	// the trusted keys are part of the key - a copy loaded without verification must never serve a registry config that requires it
	keys := sha256.Sum256([]byte(strings.Join(registryConfig.Keys, "\n")))
	key := registryConfig.GetURL() + "/" + dir + "/" + hex.EncodeToString(keys[:8])
	return d.alpineUpstreamIndexes.GetOrLoad(key, func() (*alpineUpstreamIndex, error) {
		return d.loadAlpineUpstreamIndex(context.WithoutCancel(ctx), registryConfig, dir)
	})
}

func (d *AlpineDependencyProxyController) packageBuildTime(ctx context.Context, configs DependencyProxyConfigs, requestPath string) (time.Time, error) {
	dir, file := path.Split(requestPath)
	upstream, err := d.getAlpineUpstreamIndex(ctx, alpineRegistryConfig(configs), strings.TrimSuffix(dir, "/"))
	if err != nil {
		return time.Time{}, err
	}
	return upstream.buildTimes[file], nil
}

func (d *AlpineDependencyProxyController) loadAlpineUpstreamIndex(ctx context.Context, registryConfig dtos.AlpineRegistryConfig, dir string) (*alpineUpstreamIndex, error) {
	data, _, statusCode, err := d.fetchFromUpstream(ctx, alpine, registryConfig.GetURL(), path.Join(dir, "APKINDEX.tar.gz"), nil, nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned status %d for %s/APKINDEX.tar.gz", statusCode, dir)
	}

	signature, index, err := splitAPKIndexArchive(data)
	if err != nil {
		return nil, err
	}
	verified := len(registryConfig.Keys) > 0
	if verified {
		if err := verifyAPKIndexSignature(signature, index, registryConfig.Keys); err != nil {
			return nil, fmt.Errorf("could not verify %s/APKINDEX.tar.gz: %w", dir, err)
		}
	}

	entries, err := readAPKIndexTar(index)
	if err != nil {
		return nil, err
	}
	apkIndex := slices.IndexFunc(entries, func(entry tarEntry) bool { return entry.header.Name == "APKINDEX" })
	if apkIndex == -1 {
		return nil, fmt.Errorf("APKINDEX archive contains no APKINDEX file")
	}

	buildTimes := make(map[string]time.Time)
	for _, rec := range parseAPKIndex(entries[apkIndex].data) {
		buildTimes[rec.fileName()] = rec.builtAt
	}

	size := 0
	for _, entry := range entries {
		size += len(entry.data)
	}
	return &alpineUpstreamIndex{entries: entries, apkIndex: apkIndex, buildTimes: buildTimes, verified: verified, size: size}, nil
}

func (d *AlpineDependencyProxyController) loadAlpineIndex(ctx context.Context, configs DependencyProxyConfigs, dir string) (*alpineIndex, error) {
	registryConfig := alpineRegistryConfig(configs)
	registry := registryConfig.GetURL()

	upstream, err := d.getAlpineUpstreamIndex(ctx, registryConfig, dir)
	if err != nil {
		return nil, err
	}

	filtered, removed := filterAlpineMetadata(upstream.entries[upstream.apkIndex].data, func(name, version string, released time.Time) bool {
		if released.IsZero() {
			// unknown build time counts as brand new, like on the package route
			released = time.Now()
		}
		blocked, _ := d.CheckNotAllowedPackage(newPackage(alpine, registry, "alpine/"+name, version, released), configs)
		return !blocked
	})
	if removed > 0 {
		slog.Info("Filtered alpine index", "proxy", alpine.name(), "dir", dir, "removedPackages", removed)
	}
	// the upstream entries are shared - copy before replacing the APKINDEX
	entries := slices.Clone(upstream.entries)
	entries[upstream.apkIndex].data = filtered

	archive, err := writeAPKIndexTar(entries)
	if err != nil {
		return nil, err
	}
	if upstream.verified {
		rsaKey, err := d.alpineSigningKey(ctx, configs.Secret)
		if err != nil {
			return nil, err
		}
		signature, err := signAPKIndex(archive, rsaKey)
		if err != nil {
			return nil, err
		}
		archive = append(signature, archive...)
	}

	return &alpineIndex{archive: archive, size: len(archive)}, nil
}

func filterAlpineMetadata(data []byte, allowed func(name, version string, released time.Time) bool) ([]byte, int) {
	var kept strings.Builder
	removed := 0
	for _, rec := range parseAPKIndex(data) {
		if !allowed(rec.name, rec.version, rec.builtAt) {
			removed++
			continue
		}
		kept.WriteString(rec.raw)
		kept.WriteString("\n\n")
	}
	return []byte(kept.String()), removed
}

type tarEntry struct {
	header *tar.Header
	data   []byte
}

func readAPKIndexTar(index []byte) ([]tarEntry, error) {
	gz, err := gzip.NewReader(bytes.NewReader(index))
	if err != nil {
		return nil, fmt.Errorf("failed to open APKINDEX archive: %w", err)
	}
	defer gz.Close()

	var entries []tarEntry
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read APKINDEX archive: %w", err)
		}
		data, err := utils.ReadLimited(tr, alpineIndexFileMaxBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s from APKINDEX archive: %w", header.Name, err)
		}
		entries = append(entries, tarEntry{header: header, data: data})
	}
}

func writeAPKIndexTar(entries []tarEntry) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		header := *entry.header
		header.Size = int64(len(entry.data))
		if err := tw.WriteHeader(&header); err != nil {
			return nil, err
		}
		if _, err := tw.Write(entry.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type apkIndexRecord struct {
	name    string    // P:
	version string    // V:
	builtAt time.Time // t:, zero if missing or unparsable
	raw     string    // verbatim, so a filtered index is written back unchanged
}

func (r apkIndexRecord) fileName() string { return r.name + "-" + r.version + ".apk" }

func parseAPKIndex(content []byte) []apkIndexRecord {
	var records []apkIndexRecord
	for raw := range strings.SplitSeq(string(content), "\n\n") {
		// extra blank lines leave empty records or leading newlines behind
		raw = strings.Trim(raw, "\n")
		if raw == "" {
			continue
		}

		rec := apkIndexRecord{raw: raw}
		for line := range strings.SplitSeq(raw, "\n") {
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			switch key {
			case "P":
				rec.name = value
			case "V":
				rec.version = value
			case "t":
				if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
					rec.builtAt = time.Unix(seconds, 0)
				}
			}
		}
		if rec.name == "" || rec.version == "" {
			continue
		}
		records = append(records, rec)
	}
	return records
}
