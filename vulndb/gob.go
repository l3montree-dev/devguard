package vulndb

import (
	"archive/tar"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/datatypes"
)

// CISAKEVEntry is the gob-safe representation of a CISA KEV record.
// Dates are stored as *time.Time to avoid the datatypes.Date gob limitation.
type CISAKEVEntry struct {
	CVE               string
	ExploitAddDate    *time.Time
	ActionDueDate     *time.Time
	RequiredAction    string
	VulnerabilityName string
}

// GobExploit is the gob-safe representation of models.Exploit.
// It omits the nested CVE field which contains datatypes.Date.
type GobExploit struct {
	ID          string
	Published   *time.Time
	Updated     *time.Time
	Author      string
	Type        string
	Verified    bool
	SourceURL   string
	Description string
	CVEID       string
	Tags        string
	Forks       int
	Watchers    int
	Subscribers int
	Stars       int
}

// GobMaliciousComponent is the gob-safe representation of models.MaliciousAffectedComponent.
type GobMaliciousComponent struct {
	ID                 string
	MaliciousPackageID string
	PurlWithoutVersion string
	Ecosystem          string
	Version            *string
	SemverIntroduced   *string
	SemverFixed        *string
	VersionIntroduced  *string
	VersionFixed       *string
}

// GobMaliciousPackagesExport bundles the full malicious-packages snapshot.
// models.MaliciousPackage only contains plain types and is gob-safe directly.
type GobMaliciousPackagesExport struct {
	Package    models.MaliciousPackage
	Components []GobMaliciousComponent
}

// --- CISA KEV conversions ---

func cisaKEVEntriesToGob(cves []models.CVE) []CISAKEVEntry {
	out := make([]CISAKEVEntry, 0, len(cves))
	for _, c := range cves {
		out = append(out, CISAKEVEntry{
			CVE:               c.CVE,
			ExploitAddDate:    dateToTimePtr(c.CISAExploitAdd),
			ActionDueDate:     dateToTimePtr(c.CISAActionDue),
			RequiredAction:    c.CISARequiredAction,
			VulnerabilityName: c.CISAVulnerabilityName,
		})
	}
	return out
}

func dateToTimePtr(d *datatypes.Date) *time.Time {
	if d == nil {
		return nil
	}
	t := time.Time(*d)
	return &t
}

// --- Exploit conversions ---

func exploitToGob(e models.Exploit) GobExploit {
	return GobExploit{
		ID:          e.ID,
		Published:   e.Published,
		Updated:     e.Updated,
		Author:      e.Author,
		Type:        e.Type,
		Verified:    e.Verified,
		SourceURL:   e.SourceURL,
		Description: e.Description,
		CVEID:       e.CVEID,
		Tags:        e.Tags,
		Forks:       e.Forks,
		Watchers:    e.Watchers,
		Subscribers: e.Subscribers,
		Stars:       e.Stars,
	}
}

func gobExploitToModel(g GobExploit) models.Exploit {
	return models.Exploit{
		ID:          g.ID,
		Published:   g.Published,
		Updated:     g.Updated,
		Author:      g.Author,
		Type:        g.Type,
		Verified:    g.Verified,
		SourceURL:   g.SourceURL,
		Description: g.Description,
		CVEID:       g.CVEID,
		Tags:        g.Tags,
		Forks:       g.Forks,
		Watchers:    g.Watchers,
		Subscribers: g.Subscribers,
		Stars:       g.Stars,
	}
}

// --- Malicious package conversions ---

func maliciousComponentToGob(c models.MaliciousAffectedComponent) GobMaliciousComponent {
	return GobMaliciousComponent{
		ID:                 c.ID,
		MaliciousPackageID: c.MaliciousPackageID,
		PurlWithoutVersion: c.PurlWithoutVersion,
		Ecosystem:          c.Ecosystem,
		Version:            c.Version,
		SemverIntroduced:   c.SemverIntroduced,
		SemverFixed:        c.SemverFixed,
		VersionIntroduced:  c.VersionIntroduced,
		VersionFixed:       c.VersionFixed,
	}
}

func gobComponentToModel(g GobMaliciousComponent) models.MaliciousAffectedComponent {
	return models.MaliciousAffectedComponent{
		ID:                 g.ID,
		MaliciousPackageID: g.MaliciousPackageID,
		PurlWithoutVersion: g.PurlWithoutVersion,
		Ecosystem:          g.Ecosystem,
		Version:            g.Version,
		SemverIntroduced:   g.SemverIntroduced,
		SemverFixed:        g.SemverFixed,
		VersionIntroduced:  g.VersionIntroduced,
		VersionFixed:       g.VersionFixed,
	}
}

func writeGobFileItems[T any](items []T, fileName string) error {
	gobFile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("could not create gob file: %w", err)
	}
	defer gobFile.Close()
	encoder := gob.NewEncoder(gobFile)
	for i := range items {
		if err := encoder.Encode(items[i]); err != nil {
			return fmt.Errorf("could not encode item to gob file: %w", err)
		}
	}
	return nil
}

func writeGobFile(object any, fileName string) error {
	gobFile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("could not create gob file: %w", err)
	}
	defer gobFile.Close()
	if err := gob.NewEncoder(gobFile).Encode(object); err != nil {
		return fmt.Errorf("could not encode object to gob file: %w", err)
	}
	return nil
}

// readAllGobItems decodes all individually-encoded items from a gob stream into a slice.
func readAllGobItems[T any](path string) ([]T, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open gob file %s: %w", path, err)
	}
	defer fd.Close()
	decoder := gob.NewDecoder(fd)
	var items []T
	for {
		var item T
		if err := decoder.Decode(&item); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("could not decode gob file %s: %w", path, err)
		}
		items = append(items, item)
	}
	return items, nil
}

// readGobFile is the counterpart of writeGobFile — decodes a plain gob file.
func readGobFile(path string, out any) error {
	fd, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("could not open gob file %s: %w", path, err)
	}
	defer fd.Close()
	if err := gob.NewDecoder(fd).Decode(out); err != nil {
		return fmt.Errorf("could not decode gob file %s: %w", path, err)
	}
	return nil
}

var batchSize = 5_000

func readGobFileStream[T any, Transformed any](ctx context.Context, path string, out chan<- Transformed, transformer func([]T) Transformed) error {
	fd, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("could not open gob file %s: %w", path, err)
	}
	defer fd.Close()
	decoder := gob.NewDecoder(fd)
	batch := make([]T, 0, batchSize)
	for {
		var item T
		if err := decoder.Decode(&item); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("could not decode gob file %s: %w", path, err)
		}
		batch = append(batch, item)
		if len(batch) == batchSize {
			select {
			case out <- transformer(batch):
			case <-ctx.Done():
				return ctx.Err()
			}
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		select {
		case out <- transformer(batch):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func writeVulnDBTarZst(tarZstFileName string, fileNames []string) error {
	outFile, err := os.Create(tarZstFileName)
	if err != nil {
		return fmt.Errorf("could not create tar.zst file: %w", err)
	}
	defer outFile.Close()

	zstdWriter, err := zstd.NewWriter(outFile,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(22)),
		zstd.WithWindowSize(zstd.MaxWindowSize),
	)
	if err != nil {
		return fmt.Errorf("could not create zstd writer: %w", err)
	}
	defer zstdWriter.Close()

	tarWriter := tar.NewWriter(zstdWriter)
	defer tarWriter.Close()

	for _, fileName := range fileNames {
		inputFile, err := os.Open(fileName)
		if err != nil {
			return fmt.Errorf("could not open %s: %w", fileName, err)
		}

		info, err := inputFile.Stat()
		if err != nil {
			inputFile.Close()
			return fmt.Errorf("could not stat %s: %w", fileName, err)
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			inputFile.Close()
			return fmt.Errorf("could not build tar header for %s: %w", fileName, err)
		}
		header.Name = filepath.Base(fileName)

		if err := tarWriter.WriteHeader(header); err != nil {
			inputFile.Close()
			return fmt.Errorf("could not create tar entry for %s: %w", fileName, err)
		}
		if _, err := io.Copy(tarWriter, inputFile); err != nil {
			inputFile.Close()
			return fmt.Errorf("could not write %s to tar: %w", fileName, err)
		}
		if err := inputFile.Close(); err != nil {
			return fmt.Errorf("could not close %s: %w", fileName, err)
		}
	}

	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("could not finalize tar file: %w", err)
	}
	return nil
}

func untarZstd(src, dest string) error {
	fd, err := os.Open(src)
	if err != nil {
		return err
	}
	defer fd.Close()

	zstdReader, err := zstd.NewReader(fd)
	if err != nil {
		return fmt.Errorf("could not create zstd reader: %w", err)
	}
	defer zstdReader.Close()

	tarReader := tar.NewReader(zstdReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		fpath := filepath.Join(dest, header.Name)
		if header.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, header.FileInfo().Mode())
		if err != nil {
			return err
		}

		if _, err := io.Copy(outFile, tarReader); err != nil {
			outFile.Close()
			return err
		}
		if err := outFile.Close(); err != nil {
			return err
		}
	}
}
