package commands

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/licensecheck"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	xz "github.com/ulikunitz/xz"
)

const baseFolder string = "internal/core/component/"

var (
	alpineReleaseVersions []string
	alpineLicenseMap      map[string]string = make(map[string]string, 100*1000) // Map to cache alpine type licenses. Form : <package name> + <package version> -> license (size is an upper bound)
)

func NewLicensesCommand() *cobra.Command {
	licenses := cobra.Command{
		Use:   "licenses",
		Short: "licenses",
	}

	licenses.AddCommand(newUpdateLicensesCommand())
	return &licenses
}

func newUpdateLicensesCommand() *cobra.Command {
	updateLicenses := &cobra.Command{
		Use:   "update",
		Short: "Will fetch approved license and alpine license information and write it to the respective file",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			start := time.Now()

			err = updateApprovedLicenses()
			if err != nil {
				slog.Error("error when trying to update approved licenses, continuing...\n", "err", err)
			}

			err = updateAlpineLicenses()
			if err != nil {
				slog.Error("error when trying to update alpine licenses, continuing...\n", "err", err)
			}

			if len(args) >= 1 && args[0] == "all" {
				err = updateDebianLicenses()
				if err != nil {
					slog.Error("error when trying to update debian licenses, continuing...\n", "err", err)
				}
			}

			slog.Info(fmt.Sprintf("finished updating license, done in %f seconds", time.Since(start).Seconds()))
			return err
		},
	}
	return updateLicenses
}

func updateApprovedLicenses() error {
	apiURL := "https://raw.githubusercontent.com/spdx/license-list-data/refs/heads/main/json/licenses.json"
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("could not build the http request: %s", err)
	}
	client := http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http request to %s was unsuccessful (code: %d)", apiURL, resp.StatusCode)
	}

	path := "internal/core/component/approved-licenses.json"
	fileDescriptor, err := os.Create(path)
	if err != nil {
		return err
	}
	defer fileDescriptor.Close()
	_, err = io.Copy(fileDescriptor, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func updateAlpineLicenses() error {

	err := retrieveAlpineVersions()
	if err != nil {
		return err
	}
	for _, version := range alpineReleaseVersions {
		versionURL := fmt.Sprintf("https://dl-cdn.alpinelinux.org/%s/main/x86_64/APKINDEX.tar.gz", version)
		apkIndex, err := getAPKIndexInformation(versionURL)
		if err != nil {
			return err
		}
		extractLicensesFromAPKINDEX(*apkIndex)
	}
	path := baseFolder + "alpine-licenses.json"
	err = writeLicenseMapToFile(&alpineLicenseMap, path)
	if err != nil {
		return err
	}

	return nil
}

func updateDebianLicenses() error {
	fileList, err := getFileListYAML()
	if err != nil {
		return err
	}

	debianLicenseMap, err := getLicensesFromFileList(fileList)
	if err != nil {
		return err
	}

	path := baseFolder + "debian-licenses.json"
	err = writeLicenseMapToFile(&debianLicenseMap, path)
	if err != nil {
		return err
	}
	return nil
}

func writeLicenseMapToFile(licenses *map[string]string, path string) error {
	fileDescriptor, err := os.Create(path)
	if err != nil {
		return err
	}
	defer fileDescriptor.Close()
	buf := bufio.NewWriterSize(fileDescriptor, len(*licenses))
	encoder := json.NewEncoder(buf)
	err = encoder.Encode(*licenses)
	if err != nil {
		return err
	}
	err = buf.Flush()
	if err != nil {
		return err
	}
	return nil
}

func getAPKIndexInformation(url string) (*bytes.Buffer, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &bytes.Buffer{}, err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return &bytes.Buffer{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return &bytes.Buffer{}, fmt.Errorf("http request was unsuccessful, status code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	buf := bytes.Buffer{}
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return &bytes.Buffer{}, err
	}

	unzippedContents, err := gzip.NewReader(&buf)
	if err != nil {
		return &bytes.Buffer{}, err
	}
	defer unzippedContents.Close()

	tarContents := tar.NewReader(unzippedContents)
	apkIndex := bytes.NewBuffer(make([]byte, 0, 2*1000*1000)) // allocate 2 MB memory for buf to avoid resizing operations
	for {                                                     //go through every file
		header, err := tarContents.Next()
		if err == io.EOF {
			break // end of tar archive
		}
		if err != nil {
			log.Fatal(err)
		}
		if header.Name == "APKINDEX" {
			_, err = apkIndex.ReadFrom(tarContents)
			if err != nil {
				return &bytes.Buffer{}, err
			}
		}
	}
	return apkIndex, nil
}

// splits contents into blocks separated by two new line characters. Then iterate over every block to extract package name, version and license using string modifications
func extractLicensesFromAPKINDEX(contents bytes.Buffer) {
	var name, version, license string
	var indexName, indexVersion, indexLicense int
	for pkg := range strings.SplitSeq(contents.String(), "\n\n") {
		indexName = strings.Index(pkg, "\nP:")
		if indexName != -1 { // first check package name
			name, _, _ = strings.Cut(pkg[indexName+3:], "\n")
			indexVersion = strings.Index(pkg[indexName+len(name):], "\nV:") // reduce operations by starting the search after the package field
			if indexVersion != -1 {                                         // then check version
				version, _, _ = strings.Cut(pkg[indexName+len(name)+indexVersion+3:], "\n")
				indexLicense = strings.Index(pkg[indexName+len(name)+indexVersion+len(version):], "\nL:")
				if indexLicense != -1 { // last check the license
					license, _, _ = strings.Cut(pkg[indexName+len(name)+indexVersion+len(version)+indexLicense+3:], "\n") // reduce operations by starting the search after the version field
					alpineLicenseMap[name+version] = license
				}
			}
		}
	}
}

func retrieveAlpineVersions() error {
	buf := bytes.NewBuffer(make([]byte, 0, 64*1000)) // json size is roughly 64 KB
	releasesURL := "https://alpinelinux.org/releases.json"
	req, err := http.NewRequest("GET", releasesURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return err
	}

	type releases struct {
		ReleaseBranches []struct {
			Branch string `json:"rel_branch"`
		} `json:"release_branches"`
	}
	r := releases{}
	err = json.Unmarshal(buf.Bytes(), &r)
	if err != nil {
		return err
	}
	alpineReleaseVersions = make([]string, 0, len(r.ReleaseBranches))
	for _, rls := range r.ReleaseBranches {
		if rls.Branch[1] == '3' || rls.Branch == "edge" { //only check versions 3.x and edge
			alpineReleaseVersions = append(alpineReleaseVersions, rls.Branch)
		}
	}
	return nil
}

func getFileListYAML() (*bytes.Buffer, error) {
	url := "https://metadata.ftp-master.debian.org/changelogs/filelist.yaml.xz"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return &bytes.Buffer{}, err
	}
	client := http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return &bytes.Buffer{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return &bytes.Buffer{}, fmt.Errorf("request was not successful, status code: %d", resp.StatusCode)
	}
	buf := bytes.NewBuffer(make([]byte, 0, 1<<20))

	reader, err := xz.NewReader(resp.Body)
	if err != nil {
		return buf, err
	}
	_, err = io.Copy(buf, reader)
	if err != nil {
		return buf, err
	}
	return buf, nil
}

func getLicensesFromFileList(fileList *bytes.Buffer) (map[string]string, error) {
	var licenseMap map[string]string //map to hold the license
	baseURL := "https://metadata.ftp-master.debian.org/changelogs/"
	urls := make([]string, 0, 200*1000)
	for field := range strings.SplitSeq(fileList.String(), "_copyright\n") { //only get the urls of the copyright files for each package and version
		lines := strings.Split(field, "\n")                                     // cut off everything in front of the copyright url by taking only the last line = lines[len(lines)-1]
		if len(lines) > 1 && strings.Count(lines[len(lines)-1][4:], "_") == 1 { //len(lines) > 1 if we have less its an invalid url, count "_" to exclude irrelevant urls like testing,stable, etc.
			urls = append(urls, lines[len(lines)-1][4:]+"_copyright") // split removes the substring so we need to add it once again
		}
	}
	type licenseTask struct { // contains all information a go routine needs to get a license and write it to the map
		url            string
		packageName    string
		packageVersion string
	}

	wg := sync.WaitGroup{} //sync main thread and go routines and make the access to the map threadsafe
	mapMutex := sync.Mutex{}
	channel := make(chan licenseTask)

	mumberOfGoRoutines := 15
	wg.Add(mumberOfGoRoutines)

	licenseMap = make(map[string]string, len(urls))
	client := http.Client{
		Timeout: 10 * time.Second,
	}

	for range mumberOfGoRoutines {
		go func() {
			buf := bytes.NewBuffer(make([]byte, 0, 20*1000))
			defer wg.Done()
			for {
				buf.Reset()
				task, ok := <-channel
				if !ok {
					return
				}

				req, err := http.NewRequest(http.MethodGet, baseURL+task.url, nil)
				if err != nil {
					slog.Error("error when building request", "error", err, "url", baseURL+task.url)
					continue //swallow errors
				}

				resp, err := client.Do(req)
				if err != nil {
					slog.Error("error when sending request", "error", err, "url", baseURL+task.url)
					continue //swallow errors
				}
				defer resp.Body.Close()
				if resp.StatusCode != 200 {
					slog.Error("invalid status code in response", "code", resp.StatusCode, "url", baseURL+task.url)
					resp.Body.Close()
					continue //swallow errors
				}

				_, err = io.Copy(buf, resp.Body)
				if err != nil {
					slog.Error("error when trying to copy response", "error", err, "url", baseURL+task.url)
					resp.Body.Close()
					continue //swallow errors
				}

				cov := licensecheck.Scan(buf.Bytes()) // use google/licensecheck to guess the license and then use the most likely result
				if len(cov.Match) > 0 {
					mapMutex.Lock()
					licenseMap[task.packageName+task.packageVersion] = cov.Match[0].ID
					mapMutex.Unlock()
				}
				resp.Body.Close()
			}

		}()
	}

	bar := progressbar.Default(int64(len(urls))) // progress bar for the user to estimate time
	for i := range urls {
		lastField := urls[i][strings.LastIndex(urls[i], "/")+1 : len(urls[i])-9] // we need the package Name and version as keys for our map
		fields := strings.Split(lastField, "_")
		packageName := fields[0]
		packageVersion := fields[1]
		channel <- licenseTask{ //pass the next task through a channel for a waiting go routine to catch
			url:            urls[i],
			packageName:    packageName,
			packageVersion: packageVersion,
		}
		bar.Add(1) //nolint:all
	}
	close(channel) // tell go routines all task are distributed
	wg.Wait()      // wait for the last go routine to finish
	return licenseMap, nil
}
