package commands

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

type PackageMapping struct {
	Debian map[string]string `json:"debian"`
	Alpine map[string]string `json:"alpine"`
}

func newAliasMappingCommand() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "alias-mapping",
		Short: "Generates package alias mappings for Debian and Alpine",
		Args:  cobra.MaximumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			mapping := PackageMapping{
				Debian: make(map[string]string),
				Alpine: make(map[string]string),
			}

			slog.Info("Generating Debian package mappings...")
			if err := generateDebianMappings(&mapping); err != nil {
				slog.Error("Error generating Debian mappings", "err", err)
			}

			slog.Info("Generating Alpine package mappings...")
			if err := generateAlpineMappings(&mapping); err != nil {
				slog.Error("Error generating Alpine mappings", "err", err)
			}

			// Remove identical mappings
			removeIdenticalMappings(mapping.Debian)
			removeIdenticalMappings(mapping.Alpine)

			// Write to JSON file
			output, err := json.MarshalIndent(mapping, "", "  ")
			if err != nil {
				slog.Error("could not marshal mappings to JSON", "err", err)
				os.Exit(1)
			}

			if err := os.WriteFile("package_mappings.json", output, 0644); err != nil {
				slog.Error("could not write file", "err", err)
				os.Exit(1)
			}

			slog.Info("Package mappings generated successfully: package_mappings.json")
		},
	}

	return importCmd
}

// Add this before writing JSON
func removeIdenticalMappings(m map[string]string) {
	for pkg, src := range m {
		if pkg == src {
			delete(m, pkg)
		}
	}
}

func generateDebianMappings(mapping *PackageMapping) error {
	// Multiple Debian versions for better coverage
	// Trixie (13) - testing, Bookworm (12) - current stable, Bullseye (11) - oldstable
	repos := []string{
		// Trixie (13)
		"http://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.gz",
		"http://deb.debian.org/debian/dists/trixie/contrib/binary-amd64/Packages.gz",
		"http://deb.debian.org/debian/dists/trixie/non-free/binary-amd64/Packages.gz",
		// Bookworm (12)
		"http://deb.debian.org/debian/dists/bookworm/main/binary-amd64/Packages.gz",
		"http://deb.debian.org/debian/dists/bookworm/contrib/binary-amd64/Packages.gz",
		"http://deb.debian.org/debian/dists/bookworm/non-free/binary-amd64/Packages.gz",
		// Bullseye (11)
		"http://deb.debian.org/debian/dists/bullseye/main/binary-amd64/Packages.gz",
		"http://deb.debian.org/debian/dists/bullseye/contrib/binary-amd64/Packages.gz",
		"http://deb.debian.org/debian/dists/bullseye/non-free/binary-amd64/Packages.gz",
	}

	for _, url := range repos {
		fmt.Printf("  Fetching %s\n", url)
		if err := parseDebianPackages(url, mapping.Debian); err != nil {
			return fmt.Errorf("failed to parse %s: %w", url, err)
		}
	}

	return nil
}

var neverMapToSource = []*regexp.Regexp{
	regexp.MustCompile(`^linux$`),
}
var doNeverMap = []*regexp.Regexp{
	regexp.MustCompile(`^git-man$`),
}

func matchesAny(s string, patterns []*regexp.Regexp) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(s) {
			return true
		}
	}
	return false
}

func parseDebianPackages(url string, mapping map[string]string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	scanner := bufio.NewScanner(gzReader)
	// Increase buffer size to handle long lines in Debian packages
	// Some Description fields can be very long
	const maxCapacity = 1024 * 1024 // 1MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)
	var currentPackage string

	for scanner.Scan() {
		line := scanner.Text()

		if after, ok := strings.CutPrefix(line, "Package: "); ok {
			currentPackage = after
			if matchesAny(currentPackage, doNeverMap) {
				currentPackage = ""
			}
		} else if after0, ok0 := strings.CutPrefix(line, "Source: "); ok0 {
			source := after0
			if matchesAny(source, neverMapToSource) {
				continue
			}
			// Source field might contain version info like "glibc (2.31-1)"
			// Extract just the package name
			if idx := strings.Index(source, " "); idx > 0 {
				source = source[:idx]
			}
			if currentPackage != "" {
				mapping[currentPackage] = source
			}
		} else if line == "" {
			// Empty line marks end of package entry
			// If no Source field was found, package name == source name
			if currentPackage != "" && mapping[currentPackage] == "" {
				mapping[currentPackage] = currentPackage
			}
			currentPackage = ""
		}
	}

	return scanner.Err()
}

func generateAlpineMappings(mapping *PackageMapping) error {
	// Multiple Alpine versions for better coverage
	repos := []string{
		// v3.20 - latest stable
		"https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/APKINDEX.tar.gz",
		"https://dl-cdn.alpinelinux.org/alpine/v3.20/community/x86_64/APKINDEX.tar.gz",
		// v3.19
		"https://dl-cdn.alpinelinux.org/alpine/v3.19/main/x86_64/APKINDEX.tar.gz",
		"https://dl-cdn.alpinelinux.org/alpine/v3.19/community/x86_64/APKINDEX.tar.gz",
		// v3.18
		"https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/APKINDEX.tar.gz",
		"https://dl-cdn.alpinelinux.org/alpine/v3.18/community/x86_64/APKINDEX.tar.gz",
	}

	for _, url := range repos {
		fmt.Printf("  Fetching %s\n", url)
		if err := parseAlpinePackages(url, mapping.Alpine); err != nil {
			return fmt.Errorf("failed to parse %s: %w", url, err)
		}
	}

	return nil
}

func parseAlpinePackages(url string, mapping map[string]string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Alpine APKINDEX is a tar.gz containing APKINDEX file
	// For simplicity, we'll extract and parse it
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	// Read the entire content (APKINDEX is text-based)
	content, err := io.ReadAll(gzReader)
	if err != nil {
		return err
	}

	// Parse APKINDEX format
	// Format uses blank lines to separate packages
	// P: package name
	// o: origin (source package)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	// Increase buffer size to handle long lines
	// Some package descriptions can be very long
	const maxCapacity = 1024 * 1024 // 1MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)
	var currentPackage, currentOrigin string

	for scanner.Scan() {
		line := scanner.Text()

		if after, ok := strings.CutPrefix(line, "P:"); ok {
			currentPackage = after
		} else if after0, ok0 := strings.CutPrefix(line, "o:"); ok0 {
			currentOrigin = after0
		} else if line == "" {
			// End of package entry
			if currentPackage != "" {
				if currentOrigin != "" {
					mapping[currentPackage] = currentOrigin
				} else {
					// No origin means package name == source name
					mapping[currentPackage] = currentPackage
				}
			}
			currentPackage = ""
			currentOrigin = ""
		}
	}

	return scanner.Err()
}
