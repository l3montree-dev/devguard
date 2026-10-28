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

package services

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"pault.ag/go/debian/control"
)

type DebReleaseTimeService struct {
	configService shared.ConfigService
	client        http.Client
	metasnap      *utils.LoadingCache[[]shared.MetasnapEntry]
}

var _ shared.DebReleaseTimeService = (*DebReleaseTimeService)(nil)

func NewDebReleaseTimeService(configService shared.ConfigService, client http.Client) DebReleaseTimeService {
	return DebReleaseTimeService{
		configService: configService,
		client:        client,
		metasnap:      utils.NewLoadingCache[[]shared.MetasnapEntry](metasnapCacheTTL, metasnapCacheSize, nil),
	}
}

func debPackageIndexKey(archive, suite, component, arch string) string {
	return "deb.releaseTimes." + archive + "." + suite + "." + component + "." + arch
}

func encodeDebPackageIndex(debPkgIndex shared.DebPackageIndex) (string, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	enc := gob.NewEncoder(writer)
	if err := enc.Encode(debPkgIndex); err != nil {
		return "", fmt.Errorf("encode error: %w", err)
	}

	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("gzip writer error: %w", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func decodeDebPackageIndex(s string) (shared.DebPackageIndex, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return shared.DebPackageIndex{}, fmt.Errorf("decode error: %w", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return shared.DebPackageIndex{}, err
	}

	defer reader.Close()

	var debPkgIndex shared.DebPackageIndex

	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&debPkgIndex); err != nil {
		return shared.DebPackageIndex{}, fmt.Errorf("decode error: %w", err)
	}
	return debPkgIndex, nil
}

func (s DebReleaseTimeService) LoadDebPackages(ctx context.Context, registry, archive, suite, component, arch string) (shared.DebRelease, []control.Paragraph, error) {
	release, paragraphReader, err := shared.FetchDebPackages(ctx, registry, archive, suite, component, arch)
	if err != nil {
		return shared.DebRelease{}, nil, err
	}

	packages, err := paragraphReader.All()
	if err != nil {
		return shared.DebRelease{}, nil, err
	}
	return release, packages, nil
}

func (s DebReleaseTimeService) collectDebPackageIndex(ctx context.Context, archive, suite, component, arch string) error {
	release, debPackages, err := s.LoadDebPackages(ctx, shared.DebRegistry, archive, suite, component, arch)
	if err != nil {
		return err
	}

	previous, _ := s.Load(ctx, archive, suite, component, arch)
	times, err := s.resolveReleasedAt(ctx, archive, suite, component, arch, debPackages, previous.DebPackages)
	if err != nil {
		return err
	}

	packageList := make([]shared.DebPackage, 0, len(debPackages))
	for i := range debPackages {
		packageList = append(packageList, shared.DebPackage{Paragraph: debPackages[i], ReleasedAt: times[i]})
	}

	packageIndex := shared.DebPackageIndex{
		DebRelease:  release,
		DebPackages: packageList,
	}

	encoded, err := encodeDebPackageIndex(packageIndex)
	if err != nil {
		return err
	}

	return s.configService.SetJSONConfig(ctx, debPackageIndexKey(archive, suite, component, arch), encoded)
}

func (s DebReleaseTimeService) Collect(ctx context.Context) error {
	var errs []error
	for archive, names := range shared.DebSuites {
		for _, suite := range names {
			for _, component := range shared.DebComponents {
				for _, arch := range shared.DebArchitectures {
					if err := s.collectDebPackageIndex(ctx, archive, suite, component, arch); err != nil {
						errs = append(errs, fmt.Errorf("%s/%s/%s/%s: %w", archive, suite, component, arch, err))
					}
				}
			}
		}
	}
	return errors.Join(errs...)
}

func (s DebReleaseTimeService) Load(ctx context.Context, archive, suite, component, arch string) (shared.DebPackageIndex, error) {
	var packageList string
	if err := s.configService.GetJSONConfig(ctx, debPackageIndexKey(archive, suite, component, arch), &packageList); err != nil {
		return shared.DebPackageIndex{}, err
	}

	return decodeDebPackageIndex(packageList)
}
