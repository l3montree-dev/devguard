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

package fixedversion

import (
	"runtime"
	"testing"

	"github.com/package-url/packageurl-go"
)

// BenchmarkDebianResolverLoad measures the full cost of downloading and parsing
// the Packages.xz file for bookworm/amd64. Requires network access; skip with
// -short if you only want offline benchmarks.
//
//	go test ./fixedversion/ -run=^$ -bench=BenchmarkDebianResolver -benchmem -v
func BenchmarkDebianResolverLoad(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping network benchmark with -short")
	}
	b.ReportAllocs()

	for b.Loop() {
		r := NewDebianResolver()
		_, err := r.getPackagesXZ("bookworm", "amd64")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDebianResolverMemory loads the package index once and reports the
// heap delta so you can see how much RAM the in-memory map actually occupies.
// Run with b.N=1 (benchmarks stop early when time runs out, so use -benchtime=1x).
//
//	go test ./fixedversion/ -run=^$ -bench=BenchmarkDebianResolverMemory -benchtime=1x -v
func BenchmarkDebianResolverMemory(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping network benchmark with -short")
	}

	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	r := NewDebianResolver()
	idx, err := r.getPackagesXZ("bookworm", "amd64")
	if err != nil {
		b.Fatal(err)
	}

	runtime.GC()
	runtime.ReadMemStats(&memAfter)

	heapMB := float64(memAfter.HeapInuse-memBefore.HeapInuse) / 1024 / 1024
	b.ReportMetric(heapMB, "heap-MB")
	b.ReportMetric(float64(memAfter.HeapAlloc-memBefore.HeapAlloc)/1024/1024, "alloc-MB")
	b.ReportMetric(float64(len(idx.entries)), "packages")

	// Break down where the bytes actually live.
	b.ReportMetric(float64(len(idx.data))/1024/1024, "data-MB")
	b.ReportMetric(float64(len(idx.depDict))/1024/1024, "depDict-MB")
	b.ReportMetric(float64(len(idx.depRanges)*6)/1024/1024, "depRanges-MB")
	totalDataMB := float64(len(idx.data)+len(idx.depDict)+len(idx.depRanges)*6) / 1024 / 1024
	b.ReportMetric(totalDataMB, "total-data-MB")
	b.ReportMetric(heapMB-totalDataMB, "go-overhead-MB")

	_ = idx
}

// BenchmarkDebianResolverLookup measures the per-lookup cost once the package
// index is already loaded into memory (the hot path in production).
//
//	go test ./fixedversion/ -run=^$ -bench=BenchmarkDebianResolverLookup -benchmem -v
func BenchmarkDebianResolverLookup(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping network benchmark with -short")
	}

	r := NewDebianResolver()
	if _, err := r.getPackagesXZ("bookworm", "amd64"); err != nil {
		b.Fatal(err)
	}

	pkgNames := []string{"libc6", "curl", "openssl"}

	for _, pkgName := range pkgNames {
		b.Run(pkgName, func(b *testing.B) {
			qualifiers := packageurl.QualifiersFromMap(map[string]string{
				"arch":   "amd64",
				"distro": "debian-12",
			})
			// Resolve the current version from the index before timing.
			purlNoVer := packageurl.NewPackageURL("deb", "", pkgName, "", qualifiers, "")
			meta, err := r.FetchPackageMetadata(*purlNoVer)
			if err != nil || len(meta.Versions) == 0 {
				b.Fatalf("could not resolve current version for %s: %v", pkgName, err)
			}
			purl := packageurl.NewPackageURL("deb", "", pkgName, meta.Versions[0], qualifiers, "")

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := r.FetchPackageMetadata(*purl)
				if err != nil {
					b.Fatal(err)
				}
				if res.PackageName != pkgName {
					b.Fatalf("expected package name %q, got %q", pkgName, res.PackageName)
				}
			}
		})
	}
}
