// Copyright (C) 2025 l3montree GmbH
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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	pgpv2Crypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	pgpCrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
	"github.com/l3montree-dev/devguard/config"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
	"golang.org/x/mod/semver"
)

type csafService struct {
	client http.Client
}

func NewCSAFService(client http.Client) *csafService {
	return &csafService{
		client: client,
	}
}

// not only the root product id is what we are interested in, but also all children in the tree
func getInterestedProductIDs(advisory *gocsaf.Advisory, productID string) []string {
	deps := []string{productID}

	for _, rel := range *advisory.ProductTree.RelationShips {
		if rel.RelatesToProductReference != nil && rel.ProductReference != nil && rel.FullProductName != nil {
			relatesReference := string(*rel.RelatesToProductReference)

			if productID == relatesReference {
				// add to tree
				// relatesToPurl -> productPurl
				if slices.Contains((deps), string(*rel.FullProductName.ProductID)) {
					continue
				}

				deps = append(deps, getInterestedProductIDs(advisory, string(*rel.FullProductName.ProductID))...)
			}
		}
	}
	return deps
}

func convertAdvisoryToCdxVulnerability(advisory *gocsaf.Advisory, purl packageurl.PackageURL) ([]cyclonedx.Vulnerability, error) {
	cdxVulns := make([]cyclonedx.Vulnerability, 0)

	// we need to convert the purl to the product id to find all relationships
	// those are done using product ids
	rootProductID := ""

	// collect all purls and map to product ids
	productIDtoPurl := map[string]packageurl.PackageURL{}
	// get the product id for the given purl in this advisory
	products := advisory.ProductTree.FullProductNames
	for _, product := range *products {
		// check if product identifier matches the purl
		if product.ProductIdentificationHelper == nil || product.ProductIdentificationHelper.PURL == nil {
			continue
		}

		p, err := packageurl.FromString(string(*product.ProductIdentificationHelper.PURL))
		if err != nil {
			continue
		}

		productIDtoPurl[string(*product.ProductID)] = p
		if p.ToString() == purl.ToString() {
			rootProductID = string(*product.ProductID)
		}
	}
	if rootProductID == "" {
		// this advisory does not concern the given purl
		return cdxVulns, nil
	}

	if advisory.ProductTree.RelationShips != nil {
		// add all product ids from relationships as well
		for _, ref := range *advisory.ProductTree.RelationShips {
			if ref.ProductReference != nil && ref.FullProductName != nil {
				productIDtoPurl[string(*ref.FullProductName.ProductID)] = productIDtoPurl[string(*ref.ProductReference)]
			}
		}
	}

	// get all interested product ids (children in the tree)
	// those are the product ids which relate to the given purl
	// any vulnerability affecting those product ids is relevant
	interestedProductIDs := getInterestedProductIDs(advisory, rootProductID)
	interestedPurls := make([]packageurl.PackageURL, 0)
	for _, pid := range interestedProductIDs {
		if p, ok := productIDtoPurl[pid]; ok {
			interestedPurls = append(interestedPurls, p)
		}
	}

	for _, vuln := range advisory.Vulnerabilities {
		// for now, only cve's
		if vuln.CVE == nil {
			continue
		}

		var upperBound *packageurl.PackageURL
		var lowerBound *packageurl.PackageURL
		var lowerBoundProductID *gocsaf.ProductID

		if vuln.ProductStatus == nil {
			continue
		}

		if vuln.ProductStatus.FirstAffected != nil {
			for _, productRef := range *(*vuln).ProductStatus.FirstAffected {
				if !slices.Contains(interestedProductIDs, string(*productRef)) {
					continue
				}
				// check if this product ref is of the same package compared to what we are looking for
				if !slices.Contains(interestedProductIDs, string(*productRef)) {
					// we do not care about any vulnerabilities not affecting the same package
					continue
				}
				vulnPurl := productIDtoPurl[string(*productRef)]
				if !belongsToSomeSamePackage(vulnPurl, interestedPurls) {
					// we do not care about any vulnerabilities not affecting the same package
					continue
				}
				// its the same package!
				// this is our lower bound
				lowerBound = &vulnPurl
				lowerBoundProductID = productRef
			}
		}

		if vuln.ProductStatus.FirstFixed != nil {
			for _, productRef := range *(*vuln).ProductStatus.FirstFixed {
				if !slices.Contains(interestedProductIDs, string(*productRef)) {
					continue
				}
				// check if this product ref is of the same package compared to what we are looking for
				vulnPurl := productIDtoPurl[string(*productRef)]
				if !belongsToSomeSamePackage(vulnPurl, interestedPurls) {
					// we do not care about any vulnerabilities not affecting the same package
					continue
				}
				// its the same package!
				// this is our upper bound
				upperBound = &vulnPurl
			}
		}

		if lowerBound != nil && upperBound != nil {
			// we can check if the given purl version is in between the bounds
			affectedPurl, err := isInVersionRange(interestedPurls, *lowerBound, *upperBound)
			if err == nil {
				// add this vulnerability to the list
				cdxVulns = append(cdxVulns, convertCsafVulnToCdxVuln(*lowerBoundProductID, affectedPurl, cyclonedx.IASExploitable, vuln))
			}
		}

		if vuln.ProductStatus.KnownAffected != nil {
			// check if it is not a range but it just says, this purl is under investigation, fixed or affected
			for _, productRef := range *(*vuln).ProductStatus.KnownAffected {
				if !slices.Contains(interestedProductIDs, string(*productRef)) {
					continue
				}
				// check if this product ref is of the same package compared to what we are looking for
				vulnPurl := productIDtoPurl[string(*productRef)]
				if !hasExactFit(vulnPurl, interestedPurls) {
					// we do not care about any vulnerabilities not affecting the same package
					continue
				}
				// its the same package!
				cdxVulns = append(cdxVulns, convertCsafVulnToCdxVuln(*productRef, vulnPurl, cyclonedx.IASExploitable, vuln))
			}
		}

		if vuln.ProductStatus.KnownNotAffected != nil {
			for _, productRef := range *(*vuln).ProductStatus.KnownNotAffected {
				if !slices.Contains(interestedProductIDs, string(*productRef)) {
					continue
				}
				// check if this product ref is of the same package compared to what we are looking for
				vulnPurl := productIDtoPurl[string(*productRef)]
				if !hasExactFit(vulnPurl, interestedPurls) {
					// we do not care about any vulnerabilities not affecting the same package
					continue
				}
				// its the same package!
				cdxVulns = append(cdxVulns, convertCsafVulnToCdxVuln(*productRef, vulnPurl, cyclonedx.IASNotAffected, vuln))
			}
		}

		if vuln.ProductStatus.UnderInvestigation != nil {
			for _, productRef := range *(*vuln).ProductStatus.UnderInvestigation {
				if !slices.Contains(interestedProductIDs, string(*productRef)) {
					continue
				}
				// check if this product ref is of the same package compared to what we are looking for
				vulnPurl := productIDtoPurl[string(*productRef)]
				if !hasExactFit(vulnPurl, interestedPurls) {
					// we do not care about any vulnerabilities not affecting the same package
					continue
				}
				// its the same package!
				cdxVulns = append(cdxVulns, convertCsafVulnToCdxVuln(*productRef, vulnPurl, cyclonedx.IASInTriage, vuln))
			}
		}
	}
	return cdxVulns, nil
}

func (service csafService) GetVexFromCsafProvider(purl packageurl.PackageURL, ref string, realURL, domain string) (*normalize.CdxBom, error) {
	// download all advisories
	advisories, err := service.downloadCsafReports(domain)
	if err != nil {
		return nil, err
	}

	cdxVulns := make([]cyclonedx.Vulnerability, 0)
	for _, advisory := range advisories {
		vulns, err := convertAdvisoryToCdxVulnerability(&advisory, purl)
		if err != nil {
			return nil, err
		}
		cdxVulns = append(cdxVulns, vulns...)
	}

	dependencyPurls := utils.Flat(utils.Map(cdxVulns, func(el cyclonedx.Vulnerability) []string {
		if el.Affects == nil {
			return []string{}
		}
		return utils.Map(*el.Affects, func(aff cyclonedx.Affects) string {
			return aff.Ref
		})
	}))

	// now build a simple cyclonedx vex bom
	bom := &cyclonedx.BOM{
		SpecVersion:     cyclonedx.SpecVersion1_6,
		BOMFormat:       cyclonedx.BOMFormat,
		Vulnerabilities: &cdxVulns,
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				Type:   cyclonedx.ComponentTypeApplication,
				Name:   "root",
				BOMRef: "root",
			},
		},
		Components: &[]cyclonedx.Component{
			{
				BOMRef: "root",
			},
			{
				BOMRef:     purl.ToString(),
				Type:       cyclonedx.ComponentTypeApplication,
				PackageURL: purl.ToString(),
				Name:       purl.ToString(),
				Version:    purl.Version,
			},
		},
		Dependencies: &[]cyclonedx.Dependency{
			{
				Ref: "root",
				Dependencies: &[]string{
					purl.ToString(),
				},
			},
			{
				Ref:          purl.ToString(),
				Dependencies: &dependencyPurls,
			},
		},
	}

	// artifact name should be something without the version
	return normalize.FromCdxBom(bom, purlToStringWithoutVersion(purl), ref, realURL), nil
}

func purlToStringWithoutVersion(purl packageurl.PackageURL) string {
	purlWithoutVersion := purl
	purlWithoutVersion.Version = ""
	return purlWithoutVersion.ToString()
}

func convertCsafVulnToCdxVuln(productID gocsaf.ProductID, affectedPurl packageurl.PackageURL, analysisState cyclonedx.ImpactAnalysisState, vuln *gocsaf.Vulnerability) cyclonedx.Vulnerability {
	remediation := ""
	for _, rem := range vuln.Remediations {
		// check if the productID is related to the remediation
		for _, productRef := range *rem.ProductIds {
			if productID == *productRef {
				remediation = *rem.Details
			}
		}
	}

	if remediation == "" {
		// check if we find a note which has a title: "Justification for <product combination>"
		expectedTitle := fmt.Sprintf("Justification for %s", productID)
		for _, note := range vuln.Notes {
			if note.Title != nil && *note.Title == expectedTitle && note.Text != nil {
				remediation = *note.Text
			}
		}
	}

	var justification cyclonedx.ImpactAnalysisJustification
	// check if there is any flag related to this productID
	for _, flag := range vuln.Flags {
		for _, productRef := range *flag.ProductIds {
			if productID == *productRef {
				justification = cyclonedx.ImpactAnalysisJustification(string(*flag.Label))
				if remediation == "" {
					remediation = string(*flag.Label)
				}
			}
		}
	}

	cdxVuln := cyclonedx.Vulnerability{
		ID: string(*vuln.CVE),
		Affects: utils.Ptr([]cyclonedx.Affects{
			{
				Ref: affectedPurl.ToString(),
			},
		}),
		Analysis: &cyclonedx.VulnerabilityAnalysis{
			State:         analysisState,
			Justification: justification,
			// check for remediation and map to justification
			Detail: remediation,
		},
	}

	return cdxVuln
}

func isInVersionRange(purls []packageurl.PackageURL, lowerBound, upperBound packageurl.PackageURL) (packageurl.PackageURL, error) {
	// upper bound EXCLUSIVE
	// we can only do that, if the versions are semver versions
	// check if valid semver
	for _, purl := range purls {
		if !semver.IsValid(purl.Version) ||
			!semver.IsValid(lowerBound.Version) ||
			!semver.IsValid(upperBound.Version) {
			continue
		}

		result := semver.Compare(lowerBound.Version, purl.Version)
		if result > 0 {
			continue
		} else if result == 0 {
			return purl, nil
		}

		// now check upper bound
		result = semver.Compare(upperBound.Version, purl.Version)

		if result > 0 {
			return purl, nil
		}
	}
	return packageurl.PackageURL{}, fmt.Errorf("doesnt fit in version range")
}

func (service csafService) downloadCsafReports(domain string) ([]gocsaf.Advisory, error) {

	loader := gocsaf.NewProviderMetadataLoader(&service.client)

	lpmd := loader.Load(domain)
	pmdURL, err := url.Parse(lpmd.URL)
	if err != nil {
		return nil, err
	}

	afp := gocsaf.NewAdvisoryFileProcessor(
		&service.client,
		util.NewPathEval(),
		lpmd.Document,
		pmdURL,
	)

	f := make([]gocsaf.AdvisoryFile, 0)
	err = afp.Process(func(label gocsaf.TLPLabel, files []gocsaf.AdvisoryFile) error {
		f = append(f, files...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	keys, err := loadOpenPGPKeys(&service.client, lpmd.Document, util.NewPathEval())
	if err != nil {
		return nil, err
	}

	errgroup := utils.ErrGroup[gocsaf.Advisory](10)
	for _, file := range f {
		errgroup.Go(func() (gocsaf.Advisory, error) {
			return downloadAdvisory(&service.client, keys, file)
		})
	}
	return errgroup.WaitAndCollect()
}

// ref https://github.com/gocsaf/csaf/blob/main/cmd/csaf_downloader/downloader.go
type hashFetchInfo struct {
	url      string
	warn     bool
	hashType string
}

func loadHashes(client *http.Client, hashes []hashFetchInfo) ([]byte, []byte) {
	var remoteSha256, remoteSha512 []byte

	for _, h := range hashes {
		if remote, err := loadHash(client, h.url); err != nil {
			if h.warn {
				slog.Warn("Cannot fetch hash",
					"hash", h.hashType,
					"url", h.url,
					"error", err)
			} else {
				slog.Info("Hash not present", "hash", h.hashType, "file", h.url)
			}
		} else {
			switch h.hashType {
			case "sha512":
				{
					remoteSha512 = remote
				}
			case "sha256":
				{
					remoteSha256 = remote
				}
			}
		}
	}
	return remoteSha256, remoteSha512
}

// ref: https://github.com/gocsaf/csaf/blob/main/cmd/csaf_downloader/downloader.go
func loadHash(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"fetching hash from '%s' failed: %s (%d)", url, resp.Status, resp.StatusCode)
	}

	hash, err := util.HashFromReader(resp.Body)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// ref: https://github.com/gocsaf/csaf/blob/main/cmd/csaf_downloader/downloader.go
func loadSignature(client util.Client, p string) (*pgpv2Crypto.PGPSignature, error) {
	resp, err := client.Get(p)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"fetching signature from '%s' failed: %s (%d)", p, resp.Status, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	sign, err := pgpv2Crypto.NewPGPSignatureFromArmored(string(data))
	if err != nil {
		return nil, err
	}
	return sign, nil
}

func checkSignature(keys *pgpv2Crypto.KeyRing, data []byte, sign *pgpv2Crypto.PGPSignature) error {
	pm := pgpv2Crypto.NewPlainMessage(data)
	t := pgpv2Crypto.GetUnixTime()
	return keys.VerifyDetached(pm, sign, t)
}

func loadOpenPGPKeys(
	client util.Client,
	doc any,
	expr *util.PathEval,
) (*pgpv2Crypto.KeyRing, error) {
	src, err := expr.Eval("$.public_openpgp_keys", doc)
	if err != nil {
		// no keys.
		return nil, nil
	}

	var keys []gocsaf.PGPKey
	if err := util.ReMarshalJSON(&keys, src); err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return nil, nil
	}
	var result *pgpv2Crypto.KeyRing
	for i := range keys {
		key := &keys[i]
		if key.URL == nil {
			continue
		}
		u, err := url.Parse(*key.URL)
		if err != nil {
			slog.Warn("Invalid URL",
				"url", *key.URL,
				"error", err)
			continue
		}

		res, err := client.Get(u.String())
		if err != nil {
			slog.Warn(
				"Fetching public OpenPGP key failed",
				"url", u,
				"error", err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			slog.Warn(
				"Fetching public OpenPGP key failed",
				"url", u,
				"status_code", res.StatusCode,
				"status", res.Status)
			continue
		}

		ckey, err := func() (*pgpv2Crypto.Key, error) {
			defer res.Body.Close()
			return pgpv2Crypto.NewKeyFromArmoredReader(res.Body)
		}()
		if err != nil {
			slog.Warn(
				"Reading public OpenPGP key failed",
				"url", u,
				"error", err)
			continue
		}

		if !strings.EqualFold(ckey.GetFingerprint(), string(key.Fingerprint)) {
			slog.Warn(
				"Fingerprint of public OpenPGP key does not match remotely loaded",
				"url", u, "fingerprint", key.Fingerprint, "remote-fingerprint", ckey.GetFingerprint())
			continue
		}

		if result == nil {
			if keyring, err := pgpv2Crypto.NewKeyRing(ckey); err != nil {
				slog.Warn(
					"Creating store for public OpenPGP key failed",
					"url", u,
					"error", err)
			} else {
				result = keyring
			}
		} else {
			if err := result.AddKey(ckey); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

func downloadAdvisory(
	client *http.Client,
	keys *pgpv2Crypto.KeyRing,
	file gocsaf.AdvisoryFile,
) (gocsaf.Advisory, error) {
	u, err := url.Parse(file.URL())
	if err != nil {
		return gocsaf.Advisory{}, err
	}

	// Ignore not conforming filenames.
	filename := filepath.Base(u.Path)
	if !util.ConformingFileName(filename) {
		return gocsaf.Advisory{}, fmt.Errorf("not conforming file name")
	}

	resp, err := client.Get(file.URL())
	if err != nil {
		return gocsaf.Advisory{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return gocsaf.Advisory{}, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		return gocsaf.Advisory{}, fmt.Errorf("unexpected content type: %s, url: %s", ct, resp.Request.RequestURI)
	}

	var (
		writers                    []io.Writer
		s256, s512                 hash.Hash
		remoteSHA256, remoteSHA512 []byte
	)

	hashToFetch := []hashFetchInfo{}
	if file.SHA512URL() != "" {
		hashToFetch = append(hashToFetch, hashFetchInfo{
			url:      file.SHA512URL(),
			warn:     true,
			hashType: "sha512",
		})
	} else {
		slog.Info("SHA512 not present")
	}
	if file.SHA256URL() != "" {
		hashToFetch = append(hashToFetch, hashFetchInfo{
			url:      file.SHA256URL(),
			warn:     true,
			hashType: "sha256",
		})
	} else {
		slog.Info("SHA256 not present")
	}
	if file.IsDirectory() {
		for i := range hashToFetch {
			hashToFetch[i].warn = false
		}
	}

	remoteSHA256, remoteSHA512 = loadHashes(client, hashToFetch)
	if remoteSHA512 != nil {
		s512 = sha512.New()
		writers = append(writers, s512)
	}
	if remoteSHA256 != nil {
		s256 = sha256.New()
		writers = append(writers, s256)
	}

	result := bytes.NewBuffer(nil)
	writers = append(writers, result)

	// Download the advisory and hash it.
	hasher := io.MultiWriter(writers...)

	var doc gocsaf.Advisory

	tee := io.TeeReader(resp.Body, hasher)

	if err := json.NewDecoder(tee).Decode(&doc); err != nil {
		return gocsaf.Advisory{}, err
	}

	// Compare the checksums.
	s256Check := func() error {
		if s256 != nil && !bytes.Equal(s256.Sum(nil), remoteSHA256) {
			return fmt.Errorf("SHA256 checksum of %s does not match", file.URL())
		}
		return nil
	}

	s512Check := func() error {
		if s512 != nil && !bytes.Equal(s512.Sum(nil), remoteSHA512) {
			return fmt.Errorf("SHA512 checksum of %s does not match", file.URL())
		}
		return nil
	}

	// Validate OpenPGP signature.
	// we require this. If no keys or signature is present, this fails.
	keysCheck := func() error {
		var sign *pgpv2Crypto.PGPSignature
		sign, err = loadSignature(client, file.SignURL())
		if err != nil {
			return err
		}

		if err := checkSignature(keys, result.Bytes(), sign); err != nil {
			return fmt.Errorf("cannot verify signature for %s: %v", file.URL(), err)
		}

		return nil
	}

	// Validate against CSAF schema.
	schemaCheck := func() error {
		// parse the json as any
		var r any
		if err := json.Unmarshal(result.Bytes(), &r); err != nil {
			return fmt.Errorf("cannot unmarshal %q: %v", file.URL(), err)
		}

		if errors, err := gocsaf.ValidateCSAF(r); err != nil || len(errors) > 0 {
			return fmt.Errorf("schema validation for %q failed. Errors: %v", file.URL(), errors)
		}
		return nil
	}

	for _, check := range []func() error{
		s256Check,
		s512Check,
		keysCheck,
		schemaCheck,
	} {
		if err := check(); err != nil {
			return gocsaf.Advisory{}, err
		}
	}

	return doc, nil
}

func belongsToSamePackage(purl1, purl2 packageurl.PackageURL) bool {
	return strings.EqualFold(purl1.Type, purl2.Type) &&
		strings.EqualFold(purl1.Namespace, purl2.Namespace) &&
		strings.EqualFold(purl1.Name, purl2.Name)
}

func belongsToSomeSamePackage(purl packageurl.PackageURL, purls []packageurl.PackageURL) bool {
	for _, p := range purls {
		if belongsToSamePackage(purl, p) {
			return true
		}
	}
	return false
}

func hasExactFit(vulnPurl packageurl.PackageURL, purls []packageurl.PackageURL) bool {
	for _, purl := range purls {
		if !belongsToSamePackage(purl, vulnPurl) || semver.Compare(vulnPurl.Version, purl.Version) != 0 {
			continue
		}
		return true
	}
	return false
}

// generate a specific csaf report version
func GenerateCSAFReport(ctx shared.Context, dependencyVulnRepository shared.DependencyVulnRepository, vulnEventRepository shared.VulnEventRepository, assetVersionRepository shared.AssetVersionRepository, cveRepository shared.CveRepository, artifactRepository shared.ArtifactRepository) (gocsaf.Advisory, error) {
	csafDoc := gocsaf.Advisory{}
	// extract context information
	cveID := ctx.Param("version")
	if cveID == "" {
		return csafDoc, fmt.Errorf("version parameter is required")
	}
	org := shared.GetOrg(ctx)
	asset := shared.GetAsset(ctx)
	// remove everything <asset-slug>_ from the beginning of the document id
	cveID = strings.ToUpper(strings.Split(cveID, ".json")[0])

	// fetch the cve from the database
	vulns, err := dependencyVulnRepository.GetDependencyVulnByCVEIDAndAssetID(nil, cveID, asset.ID)
	if err != nil {
		return csafDoc, err
	}
	if len(vulns) == 0 {
		return csafDoc, fmt.Errorf("no vulnerability found for asset %s with cve id %s", asset.Slug, cveID)
	}

	// now we can start building the document
	// just use the first vulnerability - if there are multiple, we do not currently support that
	// TODO support multiple vulnerabilities in one csaf report?

	// build trivial parts of the document field
	csafDoc.Document = &gocsaf.Document{
		CSAFVersion: utils.Ptr(gocsaf.CSAFVersion20),
		Publisher: &gocsaf.DocumentPublisher{
			Category:  utils.Ptr(gocsaf.CSAFCategoryVendor),
			Name:      &org.Name,
			Namespace: utils.Ptr("https://devguard.org"),
		},
		Title:      utils.Ptr(fmt.Sprintf("Vulnerability history of asset: %s", asset.Slug)),
		SourceLang: utils.Ptr(gocsaf.Lang("en-US")),
	}

	// TODO change tlp based off of visibility of csaf report, white for public and TLP:AMBER or TLP:RED for access protected reports
	csafDoc.Document.Distribution = &gocsaf.DocumentDistribution{
		TLP: &gocsaf.TLP{
			DocumentTLPLabel: utils.Ptr(gocsaf.TLPLabel(gocsaf.TLPLabelWhite)),
			URL:              utils.Ptr("https://first.org/tlp"),
		},
	}

	tracking, err := generateTrackingObject(asset, vulns)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.Document.Tracking = &tracking

	tree, err := generateProductTree(asset, assetVersionRepository, artifactRepository, vulns)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.ProductTree = &tree

	vulnerabilities, err := generateVulnerabilityObjects(vulns)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.Vulnerabilities = vulnerabilities

	// if we do not have any vulnerabilities we do not comply with the security framework anymore so we need to switch the category to the base profile
	if len(vulnerabilities) == 0 {
		csafDoc.Document.Category = utils.Ptr(gocsaf.DocumentCategory("csaf_base"))
	} else {
		csafDoc.Document.Category = utils.Ptr(gocsaf.DocumentCategory("csaf_vex"))
	}

	csafDoc.Document.Tracking.CurrentReleaseDate = csafDoc.Document.Tracking.RevisionHistory[len(csafDoc.Document.Tracking.RevisionHistory)-1].Date

	return csafDoc, nil
}

// generates the product tree object for a specific asset, which includes the default branch as well as all tags
func generateProductTree(asset models.Asset, assetVersionRepository shared.AssetVersionRepository, artifactRepository shared.ArtifactRepository, vulnsForCVE []models.DependencyVuln) (gocsaf.ProductTree, error) {
	tree := gocsaf.ProductTree{}
	assetVersions, err := assetVersionRepository.GetAllTagsAndDefaultBranchForAsset(nil, asset.ID)
	if err != nil {
		return tree, err
	}

	assetVersionNames := utils.Map(assetVersions, func(el models.AssetVersion) string {
		return el.Name
	})

	artifacts, err := artifactRepository.GetByAssetVersions(asset.ID, assetVersionNames)
	if err != nil {
		return tree, err
	}

	productNames := make([]*gocsaf.FullProductName, 0)
	relationships := make([]*gocsaf.Relationship, 0)
	// append each relevant asset version
	for _, artifact := range artifacts {
		artifactPurl := normalize.Purlify(artifact.ArtifactName, artifact.AssetVersionName)
		productName := &gocsaf.FullProductName{
			Name:      &artifactPurl,
			ProductID: utils.Ptr(gocsaf.ProductID(artifactPurl)),
			ProductIdentificationHelper: &gocsaf.ProductIdentificationHelper{
				PURL: utils.Ptr(gocsaf.PURL(artifactPurl)),
			},
		}
		productNames = append(productNames, productName)
	}
	// append each vulnerable component as well as their relationship to the affected artifact
	for _, vuln := range vulnsForCVE {
		// first append the component itself
		productName := &gocsaf.FullProductName{
			Name:      &vuln.ComponentPurl,
			ProductID: utils.Ptr(gocsaf.ProductID(vuln.ComponentPurl)),
			ProductIdentificationHelper: &gocsaf.ProductIdentificationHelper{
				PURL: utils.Ptr(gocsaf.PURL(vuln.ComponentPurl)),
			},
		}
		productNames = append(productNames, productName)
		// then each affected artifact
		for _, artifact := range vuln.Artifacts {
			artifactPurl := normalize.Purlify(artifact.ArtifactName, artifact.AssetVersionName)
			relationship := gocsaf.Relationship{
				Category:                  utils.Ptr(gocsaf.CSAFRelationshipCategoryDefaultComponentOf),
				ProductReference:          utils.Ptr(gocsaf.ProductID(vuln.ComponentPurl)),
				RelatesToProductReference: utils.Ptr(gocsaf.ProductID(artifactPurl)),
				FullProductName: &gocsaf.FullProductName{
					ProductIdentificationHelper: &gocsaf.ProductIdentificationHelper{
						PURL: (*gocsaf.PURL)(&vuln.ComponentPurl),
					},
					ProductID: utils.Ptr(artifactNameAndComponentPurlToProductID(artifactPurl, "", vuln.ComponentPurl)),
					Name:      utils.Ptr(fmt.Sprintf("Package %s is a default component of artifact %s", vuln.ComponentPurl, artifactPurl)),
				},
			}
			relationships = append(relationships, &relationship)
		}
	}

	tree.FullProductNames = utils.Ptr(gocsaf.FullProductNames(productNames))
	tree.RelationShips = utils.Ptr(gocsaf.Relationships(relationships))

	return tree, nil
}

func artifactNameAndComponentPurlToProductID(artifactName, assetVersionName, componentPurl string) gocsaf.ProductID {
	if assetVersionName == "" {
		return gocsaf.ProductID(fmt.Sprintf("%s|%s", artifactName, componentPurl))
	}
	return gocsaf.ProductID(fmt.Sprintf("%s@%s|%s", artifactName, assetVersionName, componentPurl))
}

// generates the vulnerability object for a specific asset at a certain timeStamp in time
func generateVulnerabilityObjects(allVulnsOfAsset []models.DependencyVuln) ([]*gocsaf.Vulnerability, error) {
	vulnerabilities := []*gocsaf.Vulnerability{}

	// maps a cve ID to a set of asset versions where it is present to reduce clutter
	cveGroups := make(map[string][]models.DependencyVuln)
	for _, vuln := range allVulnsOfAsset {
		cveGroups[vuln.CVEID] = append(cveGroups[vuln.CVEID], vuln)
	}

	// then make a vulnerability object for every cve and list the asset version in the product status property
	for cve, vulnsInGroup := range cveGroups {
		vulnObject := gocsaf.Vulnerability{
			CVE:   utils.Ptr(gocsaf.CVE(cve)),
			Title: utils.Ptr(fmt.Sprintf("Additional information about %s", cve)),
		}
		affected := map[string]struct{}{}
		notAffected := map[string]struct{}{}
		fixed := map[string]struct{}{}
		underInvestigation := map[string]struct{}{}
		flags := []*gocsaf.Flag{}
		threats := []*gocsaf.Threat{}
		for _, vuln := range vulnsInGroup {
			// determine the discovery date
			if vulnObject.DiscoveryDate == nil {
				vulnObject.DiscoveryDate = utils.Ptr(vulnsInGroup[0].CreatedAt.Format(time.RFC3339))
			} else {
				currentDiscoveryDate, err := time.Parse(time.RFC3339, *vulnObject.DiscoveryDate)
				if err == nil {
					if currentDiscoveryDate.After(vuln.CreatedAt) {
						vulnObject.DiscoveryDate = utils.Ptr(vuln.CreatedAt.Format(time.RFC3339))
					}
				}
			}

			productIDs := make([]*gocsaf.ProductID, 0)
			for _, artifact := range vuln.Artifacts {
				productIDs = append(productIDs, utils.Ptr(gocsaf.ProductID(artifactNameAndComponentPurlToProductID(artifact.ArtifactName, artifact.AssetVersionName, vuln.ComponentPurl))))
			}

			switch vuln.State {
			case dtos.VulnStateOpen:
				for _, pid := range productIDs {
					underInvestigation[string(*pid)] = struct{}{}
				}
			case dtos.VulnStateAccepted:
				lastEvent := vuln.Events[len(vuln.Events)-1]
				vulnObject.Remediations = append(vulnObject.Remediations, &gocsaf.Remediation{
					Details:    utils.Ptr(fmt.Sprintf("Accepted the risk of this vulnerability. %s", utils.SafeDereference(lastEvent.Justification))),
					ProductIds: utils.Ptr(gocsaf.Products(productIDs)),
					Category:   utils.Ptr(gocsaf.CSAFRemediationCategoryNoFixPlanned),
				})

				for _, pid := range productIDs {
					affected[string(*pid)] = struct{}{}
				}
			case dtos.VulnStateFixed:
				for _, pid := range productIDs {
					fixed[string(*pid)] = struct{}{}
				}
			case dtos.VulnStateFalsePositive:
				lastEvent := vuln.Events[len(vuln.Events)-1]
				justification := string(lastEvent.MechanicalJustification)
				if lastEvent.MechanicalJustification == "" {
					justification = string(gocsaf.CSAFFlagLabelVulnerableCodeNotInExecutePath)
				}
				vulnObject.Remediations = append(vulnObject.Remediations, &gocsaf.Remediation{
					Details:    utils.Ptr(fmt.Sprintf("Marked as false positive: %s", utils.SafeDereference(lastEvent.Justification))),
					ProductIds: utils.Ptr(gocsaf.Products(productIDs)),
					Category:   utils.Ptr(gocsaf.CSAFRemediationCategoryMitigation),
				})

				flags = append(flags, &gocsaf.Flag{
					Label:      utils.Ptr(gocsaf.FlagLabel(justification)),
					ProductIds: utils.Ptr(gocsaf.Products(productIDs)),
				})
				for _, pid := range productIDs {
					notAffected[string(*pid)] = struct{}{}
				}
			}
		}

		vulnObject.ProductStatus = &gocsaf.ProductStatus{
			Fixed: emptySliceThenNil(utils.Ptr(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(fixed)), func(el string) *gocsaf.ProductID {
				return utils.Ptr(gocsaf.ProductID(el))
			})))),
			KnownAffected: emptySliceThenNil(utils.Ptr(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(affected)), func(el string) *gocsaf.ProductID {
				return utils.Ptr(gocsaf.ProductID(el))
			})))),
			KnownNotAffected: emptySliceThenNil(utils.Ptr(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(notAffected)), func(el string) *gocsaf.ProductID {
				return utils.Ptr(gocsaf.ProductID(el))
			})))),
			UnderInvestigation: emptySliceThenNil(utils.Ptr(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(underInvestigation)), func(el string) *gocsaf.ProductID {
				return utils.Ptr(gocsaf.ProductID(el))
			})))),
		}
		vulnObject.Flags = flags
		vulnObject.Threats = threats

		notes, err := generateNotesForVulnerabilityObject(vulnsInGroup)
		if err != nil {
			return nil, err
		}
		vulnObject.Notes = notes
		vulnerabilities = append(vulnerabilities, &vulnObject)
	}

	slices.SortFunc(vulnerabilities, func(vuln1, vuln2 *gocsaf.Vulnerability) int {
		if vuln1.CVE == nil && vuln2.CVE == nil {
			return 0
		}
		if vuln1.CVE == nil {
			return 1
		}
		if vuln2.CVE == nil {
			return -1

		}
		return -strings.Compare(string(*vuln1.CVE), string(*vuln2.CVE))
	})
	return vulnerabilities, nil
}

func emptySliceThenNil(s *gocsaf.Products) *gocsaf.Products {
	if s == nil {
		return nil
	}

	if len(*s) == 0 {
		return nil
	}
	return s
}

// generate the textual summary for a vulnerability object
func generateNotesForVulnerabilityObject(vulns []models.DependencyVuln) ([]*gocsaf.Note, error) {
	if len(vulns) == 0 {
		return nil, nil
	}
	notes := []*gocsaf.Note{}

	cve := vulns[0].CVE
	cveDescription := gocsaf.Note{
		NoteCategory: utils.Ptr(gocsaf.CSAFNoteCategoryDescription),
		Title:        utils.Ptr("textual description of CVE"),
		Text:         &cve.Description,
	}

	notes = append(notes, &cveDescription)

	vulnDetails := gocsaf.Note{

		NoteCategory: utils.Ptr(gocsaf.CSAFNoteCategoryDetails),
		Title:        utils.Ptr("state of the vulnerability in the product"),
	}

	// group vulnerabilities by artifact
	artifactToVulns := map[string][]models.DependencyVuln{}
	for _, vuln := range vulns {

		for _, artifact := range vuln.Artifacts {
			key := fmt.Sprintf("%s@%s", artifact.ArtifactName, artifact.AssetVersionName)
			artifactToVulns[key] = append(artifactToVulns[key], vuln)
		}
	}

	// Generate summary for each artifact
	var summaryParts []string
	for artifact, vulns := range artifactToVulns {
		var vulnStates []string
		for _, vuln := range vulns {
			recentJustification := vuln.Events[len(vuln.Events)-1].Justification
			eventType := vuln.Events[len(vuln.Events)-1].Type
			if recentJustification != nil && eventType != dtos.EventTypeMitigate {
				id := string(artifactNameAndComponentPurlToProductID(artifact, "", vuln.ComponentPurl))
				notes = append(notes, &gocsaf.Note{
					Title:        utils.Ptr(fmt.Sprintf("Justification for %s", id)),
					NoteCategory: utils.Ptr(gocsaf.CSAFNoteCategoryDetails),
					Text:         recentJustification,
				})
			}
			vulnStates = append(vulnStates, fmt.Sprintf("%s for package %s", stateToString(vuln.State), vuln.ComponentPurl))
		}
		summaryParts = append(summaryParts, fmt.Sprintf("ProductID %s: %s", artifact, strings.Join(normalize.SortStringsSlice(vulnStates), ", ")))
	}

	vulnDetails.Text = utils.Ptr(strings.Join(normalize.SortStringsSlice(summaryParts), ", "))
	notes = append(notes, &vulnDetails)

	return notes, nil
}

// Helper function to map state to human-readable string
func stateToString(state dtos.VulnState) string {
	switch state {
	case dtos.VulnStateOpen:
		return "unhandled"
	case dtos.VulnStateAccepted:
		return "accepted"
	case dtos.VulnStateFalsePositive:
		return "marked as false positive"
	case dtos.VulnStateFixed:
		return "fixed"
	default:
		return "unknown state"
	}
}

// generate the tracking object used by the document object
func generateTrackingObject(asset models.Asset, vulns []models.DependencyVuln) (gocsaf.Tracking, error) {
	tracking := gocsaf.Tracking{}
	allEvents := make([]vulnEventWithVuln, 0)
	for _, vuln := range vulns {
		for _, event := range vuln.Events {
			allEvents = append(allEvents, vulnEventWithVuln{
				VulnEvent: event,
				Vuln:      vuln,
			})
		}
	}

	// sort them by their creation timestamp
	slices.SortFunc(allEvents, func(event1 vulnEventWithVuln, event2 vulnEventWithVuln) int {
		return event1.VulnEvent.CreatedAt.Compare(event2.VulnEvent.CreatedAt)
	})

	engineVersion := config.Version
	if engineVersion == "" {
		engineVersion = "debug"
	}
	tracking.Generator = &gocsaf.Generator{
		Engine: &gocsaf.Engine{
			Name:    utils.Ptr("DevGuard CSAF Generator"),
			Version: &engineVersion,
		},
		Date: tracking.CurrentReleaseDate,
	}

	// then we can construct the full revision history
	revisions, err := buildRevisionHistory(asset, allEvents)
	if err != nil {
		return tracking, err
	}
	if len(revisions) == 0 {
		return tracking, fmt.Errorf("missing Revision entries")
	}
	tracking.RevisionHistory = revisions

	// now we can extract the first release and current release timestamp that being the dates of the first and last revision entry
	tracking.InitialReleaseDate = revisions[0].Date
	tracking.CurrentReleaseDate = revisions[len(revisions)-1].Date

	// fill in the last attributes
	version := fmt.Sprintf("%d", len(revisions))
	tracking.ID = utils.Ptr(gocsaf.TrackingID(strings.ToUpper(version)))
	tracking.Version = utils.Ptr(gocsaf.RevisionNumber(version))
	tracking.Status = utils.Ptr(gocsaf.CSAFTrackingStatusInterim)
	return tracking, nil
}

type vulnEventWithVuln struct {
	VulnEvent models.VulnEvent
	Vuln      models.DependencyVuln
}

// builds the full revision history for an object, that being a list of all changes to all vulnerabilities associated with this asset
func buildRevisionHistory(asset models.Asset, vulnEvents []vulnEventWithVuln) ([]*gocsaf.Revision, error) {
	var revisions []*gocsaf.Revision
	// then just create a revision entry for every event group
	version := 0
	for _, event := range vulnEvents {
		revisionObject := gocsaf.Revision{
			Date: utils.Ptr(event.VulnEvent.CreatedAt.Format(time.RFC3339)),
		}
		revisionObject.Number = utils.Ptr(gocsaf.RevisionNumber(strconv.Itoa(version + 1)))
		summary, err := generateSummaryForEvent(event.Vuln, event.VulnEvent)
		if err != nil {
			continue
		}
		revisionObject.Summary = &summary
		revisions = append(revisions, &revisionObject)
		version++
	}

	return revisions, nil
}

func generateSummaryForEvent(vuln models.DependencyVuln, event models.VulnEvent) (string, error) {
	artifactNames := make([]string, 0)
	for _, artifact := range vuln.Artifacts {
		artifactNames = append(artifactNames, fmt.Sprintf("%s@%s", artifact.ArtifactName, artifact.AssetVersionName))
	}
	artifactNameString := strings.Join(normalize.SortStringsSlice(artifactNames), ", ")

	switch event.Type {
	case dtos.EventTypeDetected:
		return fmt.Sprintf("Detected vulnerability %s in package %s (%s).", vuln.CVEID, vuln.ComponentPurl, artifactNameString), nil
	case dtos.EventTypeReopened:
		return fmt.Sprintf("Reopened vulnerability %s in package %s (%s).", vuln.CVEID, vuln.ComponentPurl, artifactNameString), nil
	case dtos.EventTypeFixed:
		return fmt.Sprintf("Fixed vulnerability %s in package %s (%s).", vuln.CVEID, vuln.ComponentPurl, artifactNameString), nil
	case dtos.EventTypeAccepted:
		return fmt.Sprintf("Accepted vulnerability %s in package %s (%s).", vuln.CVEID, vuln.ComponentPurl, artifactNameString), nil
	case dtos.EventTypeFalsePositive:
		return fmt.Sprintf("Marked vulnerability %s as false positive in package %s (%s).", vuln.CVEID, vuln.ComponentPurl, artifactNameString), nil
	default:
		return "", fmt.Errorf("unknown event type: %s (%s)", event.Type, artifactNameString)
	}
}

// signs data and returns the resulting signature
func SignCSAFReport(csafJSON []byte) ([]byte, error) {
	// configure pgp profile to meet the csaf standard
	pgp := pgpCrypto.PGPWithProfile(profile.RFC4880())
	privateKeyPath := os.Getenv("CSAF_OPENPGP_PRIVATE_KEY_PATH")
	if privateKeyPath == "" {
		privateKeyPath = "csaf-openpgp-private-key.asc"
	}

	// read private key and parse to opnepgp key struct
	privateKeyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	privateKeyArmored := string(privateKeyData)
	privateKey, err := pgpCrypto.NewKeyFromArmored(privateKeyArmored)
	if err != nil {
		return nil, err
	}

	// unlock private key using the passphrase
	password := os.Getenv("CSAF_OPENPGP_PASSPHRASE")
	if password == "" {
		return nil, fmt.Errorf("could not read csaf passphrase from environment variables, check your CSAF_PASSPHRASE variable in your .env file")
	}
	unlockedKey, err := privateKey.Unlock([]byte(password))
	if err != nil {
		return nil, err
	}

	// sign the document and return signature
	signer, err := pgp.Sign().SigningKey(unlockedKey).Detached().New()
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(csafJSON, pgpCrypto.Armor)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
