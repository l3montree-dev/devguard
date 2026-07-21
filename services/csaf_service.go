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
	"context"
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
	"text/template"
	"time"

	pgpv2Crypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	pgpCrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/google/uuid"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
	"github.com/l3montree-dev/devguard/config"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

type csafService struct {
	client                   http.Client
	dependencyVulnRepository shared.DependencyVulnRepository
	dependencyVulnService    shared.DependencyVulnService
	vulnEventRepository      shared.VulnEventRepository
	assetVersionRepository   shared.AssetVersionRepository
	cveRepository            shared.CveRepository
	artifactRepository       shared.ArtifactRepository
	advisoryRepository       shared.AdvisoryRepository
}

func NewCSAFService(client http.Client, dependencyVulnRepository shared.DependencyVulnRepository, dependencyVulnService shared.DependencyVulnService, vulnEventRepository shared.VulnEventRepository, assetVersionRepository shared.AssetVersionRepository, cveRepository shared.CveRepository, artifactRepository shared.ArtifactRepository, advisoryRepository shared.AdvisoryRepository) *csafService {
	return &csafService{
		client:                   client,
		dependencyVulnRepository: dependencyVulnRepository,
		dependencyVulnService:    dependencyVulnService,
		vulnEventRepository:      vulnEventRepository,
		assetVersionRepository:   assetVersionRepository,
		cveRepository:            cveRepository,
		artifactRepository:       artifactRepository,
		advisoryRepository:       advisoryRepository,
	}
}

var _ shared.CSAFService = (*csafService)(nil) // Ensure csafService implements shared.CSAFService interface

func (service csafService) GetVexFromCsafProvider(ctx context.Context, url string) ([]gocsaf.Advisory, error) {
	// download all advisories
	advisories, err := service.downloadCsafReports(ctx, url)
	if err != nil {
		return nil, err
	}

	return advisories, nil
}

func (service csafService) GetVexFromCsafAdvisoryURL(ctx context.Context, url string) (gocsaf.Advisory, error) {
	advisory, err := downloadAdvisoryFromURL(ctx, &utils.EgressClient, url)
	if err != nil {
		return gocsaf.Advisory{}, err
	}

	return advisory, nil
}

func (service csafService) downloadCsafReports(ctx context.Context, domain string) ([]gocsaf.Advisory, error) {

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
			return downloadAdvisoryAndValidateSignature(ctx, &service.client, keys, file)
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

func downloadAdvisoryFromURL(ctx context.Context, client *http.Client, url string) (gocsaf.Advisory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	var advisory gocsaf.Advisory
	if err != nil {
		return advisory, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return advisory, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return advisory, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		return advisory, fmt.Errorf("unexpected content type: %s, url: %s", ct, resp.Request.RequestURI)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return advisory, err
	}

	err = json.Unmarshal(b, &advisory)
	return advisory, err
}

func downloadAdvisoryAndValidateSignature(ctx context.Context, client *http.Client, keys *pgpv2Crypto.KeyRing, file gocsaf.AdvisoryFile) (gocsaf.Advisory, error) {
	u, err := url.Parse(file.URL())
	if err != nil {
		return gocsaf.Advisory{}, err
	}

	// Ignore not conforming filenames.
	filename := filepath.Base(u.Path)
	if !util.ConformingFileName(filename) {
		return gocsaf.Advisory{}, fmt.Errorf("not conforming file name")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, file.URL(), nil)
	if err != nil {
		return gocsaf.Advisory{}, err
	}

	resp, err := client.Do(req)
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

// GenerateCSAFReport generates a CSAF report for a specific CVE in an asset.
func (service csafService) GenerateCSAFReport(ctx context.Context, orgName string, assetID uuid.UUID, assetName string, cveID string) (gocsaf.Advisory, error) {
	// fetch all vulns associated with this cve from the database
	vulns, err := service.dependencyVulnRepository.GetDependencyVulnByCVEIDAndAssetID(ctx, nil, cveID, assetID)
	if err != nil {
		return gocsaf.Advisory{}, err
	}
	if len(vulns) == 0 {
		return gocsaf.Advisory{}, fmt.Errorf("no vulnerability found for asset %s with cve id %s", assetName, cveID)
	}

	return service.GenerateCSAFReportForVulns(ctx, orgName, GenerateDocumentTitle(assetName, cveID), vulns)
}

// GenerateCSAFReportForVulns builds a single CSAF advisory covering all the given
// vulnerabilities. The vulnerabilities may span multiple CVEs (one CSAF vulnerability object
// per CVE) and multiple assets/artifacts (one shared product tree), which is what lets a
// release-wide report be produced from the union of its items' vulnerabilities.
func (service csafService) GenerateCSAFReportForVulns(ctx context.Context, orgName string, title *string, vulns []models.DependencyVuln) (gocsaf.Advisory, error) {
	csafDoc := gocsaf.Advisory{}
	if len(vulns) == 0 {
		return csafDoc, fmt.Errorf("no vulnerabilities to build a csaf report from")
	}

	// build static parts of the document field first
	csafDoc.Document = &gocsaf.Document{
		CSAFVersion: new(gocsaf.CSAFVersion20),
		Publisher: &gocsaf.DocumentPublisher{
			Category:  new(gocsaf.CSAFCategoryVendor),
			Name:      &orgName,
			Namespace: new("https://devguard.org"),
		},
		Title: title,
		Lang:  new(gocsaf.Lang("en-US")),
	}

	// TODO change tlp based off of visibility of csaf report, white for public and TLP:AMBER or TLP:RED for access protected reports
	csafDoc.Document.Distribution = &gocsaf.DocumentDistribution{
		TLP: &gocsaf.TLP{
			DocumentTLPLabel: new(gocsaf.TLPLabel(gocsaf.TLPLabelWhite)),
			URL:              new("https://first.org/tlp"),
		},
	}

	tracking, err := generateTrackingObject(ctx, vulns, title)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.Document.Tracking = &tracking

	tree, err := generateProductTree(ctx, vulns)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.ProductTree = &tree

	// one CSAF vulnerability object per CVE, in a stable (sorted) order
	vulnsByCVE := make(map[string][]models.DependencyVuln)
	for _, v := range vulns {
		vulnsByCVE[v.CVEID] = append(vulnsByCVE[v.CVEID], v)
	}
	vulnerabilities := []*gocsaf.Vulnerability{}
	for _, cveID := range normalize.SortStringsSlice(slices.Collect(maps.Keys(vulnsByCVE))) {
		objs, err := generateVulnerabilityObjects(ctx, cveID, vulnsByCVE[cveID], tracking.CurrentReleaseDate)
		if err != nil {
			return csafDoc, err
		}
		vulnerabilities = append(vulnerabilities, objs...)
	}
	csafDoc.Vulnerabilities = vulnerabilities

	// if we do not have any vulnerabilities we do not comply with the security framework anymore so we need to switch the category to the base profile
	if len(vulnerabilities) == 0 {
		csafDoc.Document.Category = new(gocsaf.DocumentCategory("csaf_base"))
	} else {
		csafDoc.Document.Category = new(gocsaf.DocumentCategory("csaf_vex"))
	}

	// calculate the current release date based on the latest revision event
	csafDoc.Document.Tracking.CurrentReleaseDate = csafDoc.Document.Tracking.RevisionHistory[len(csafDoc.Document.Tracking.RevisionHistory)-1].Date

	return csafDoc, nil
}

// vulnPath returns the component-only dependency path of a vuln (root -> ... -> vulnerable
// component), falling back to the vulnerable component itself when no path was recorded.
func vulnPath(vuln models.DependencyVuln) []string {
	if len(vuln.VulnerabilityPath) > 0 {
		return vuln.VulnerabilityPath
	}
	return []string{vuln.ComponentPurl}
}

// combinedProductID derives a deterministic, opaque CSAF product id representing "comp is a
// default component of parent". It is deterministic so identical path prefixes across vulns
// collapse to the same relationship, and opaque so the dependency path is expressed only
// through the relationship graph - never smuggled into the id string.
func combinedProductID(parent, comp string) string {
	return utils.HashString(parent + "\x00" + comp)
}

// leafProductID folds combinedProductID over the whole path, returning the id of the
// deepest node - the product that uniquely represents the full path to the vulnerable
// component under the given artifact.
func leafProductID(artifactPurl string, path []string) string {
	parent := artifactPurl
	for _, comp := range path {
		parent = combinedProductID(parent, comp)
	}
	return parent
}

// generateProductTree builds the CSAF product tree for a CVE. Each vulnerability path is
// encoded as a chain of standard default_component_of relationships
// (artifact <- p1 <- p2 <- ... <- vulnerable component), so the leaf product of each chain
// identifies one exact dependency path. This lets consumers - including DevGuard's own
// ingestion - address a single path rather than the whole component.
func generateProductTree(ctx context.Context, vulnsForCVE []models.DependencyVuln) (gocsaf.ProductTree, error) {
	tree := gocsaf.ProductTree{}

	productNames := make([]*gocsaf.FullProductName, 0)
	relationships := make([]*gocsaf.Relationship, 0)
	seenProduct := make(map[string]struct{})
	seenRelationship := make(map[string]struct{})

	// addBaseProduct registers a leaf FullProductName whose product id equals its purl.
	addBaseProduct := func(purl string) {
		if _, ok := seenProduct[purl]; ok {
			return
		}
		seenProduct[purl] = struct{}{}
		p := purl
		productNames = append(productNames, &gocsaf.FullProductName{
			Name:      &p,
			ProductID: new(gocsaf.ProductID(purl)),
			ProductIdentificationHelper: &gocsaf.ProductIdentificationHelper{
				PURL: new(gocsaf.PURL(purl)),
			},
		})
	}

	for _, vuln := range vulnsForCVE {
		path := vulnPath(vuln)
		// register a base product for every component along the path
		for _, comp := range path {
			addBaseProduct(comp)
		}

		for _, artifact := range vuln.Artifacts {
			artifactPurl := normalize.Purlify(artifact.ArtifactName, artifact.AssetVersionName)
			addBaseProduct(artifactPurl)

			// build the nested default_component_of chain for this path
			parent := artifactPurl
			for _, comp := range path {
				combined := combinedProductID(parent, comp)
				if _, ok := seenRelationship[combined]; !ok {
					seenRelationship[combined] = struct{}{}
					compRef := comp
					relationships = append(relationships, &gocsaf.Relationship{
						Category:                  new(gocsaf.CSAFRelationshipCategoryDefaultComponentOf),
						ProductReference:          new(gocsaf.ProductID(comp)),
						RelatesToProductReference: new(gocsaf.ProductID(parent)),
						FullProductName: &gocsaf.FullProductName{
							ProductID: new(gocsaf.ProductID(combined)),
							Name:      new(fmt.Sprintf("Package %s as a default component of %s", comp, parent)),
							ProductIdentificationHelper: &gocsaf.ProductIdentificationHelper{
								PURL: (*gocsaf.PURL)(&compRef),
							},
						},
					})
				}
				parent = combined
			}
		}
	}

	tree.FullProductNames = new(gocsaf.FullProductNames(productNames))
	tree.RelationShips = new(gocsaf.Relationships(relationships))

	return tree, nil
}

type stateDistributionOfPathsInProduct struct {
	productID           string
	TotalAmountOfPaths  int
	AmountUnhandled     int
	AmountFalsePositive int
	AmountAccepted      int
	AmountFixed         int
}

// generates the vulnerability object for a specific asset at a certain timeStamp in time
func generateVulnerabilityObjects(ctx context.Context, cveID string, allVulnsOfCVE []models.DependencyVuln, initialRelease *string) ([]*gocsaf.Vulnerability, error) {
	vulnerabilities := []*gocsaf.Vulnerability{}

	if len(allVulnsOfCVE) == 0 {
		return vulnerabilities, nil
	}

	// built the vulnerability object for the CVE
	vulnObject := gocsaf.Vulnerability{
		IDs:           []*gocsaf.VulnerabilityID{{SystemName: new("OSV (OSV.dev)"), Text: &cveID}},
		Title:         new(fmt.Sprintf("Additional information about %s", cveID)),
		DiscoveryDate: initialRelease,
	}

	// only real CVEs are allowed in the CVE attribute
	if utils.IsCVE(cveID) {
		vulnObject.CVE = (*gocsaf.CVE)(&cveID)
	}
	productStatus, flagValues, distributions, remediations := calculateVulnStateInformation(ctx, allVulnsOfCVE)

	// build and assign the notes for the vulnerability
	notes, err := generateNotesForVulnerabilityObject(allVulnsOfCVE, distributions)
	if err != nil {
		return nil, err
	}

	flags := generateFlagsForVulnerabilityObject(flagValues)
	vulnObject.Flags = flags
	vulnObject.Notes = notes
	vulnObject.Remediations = remediations
	vulnObject.ProductStatus = productStatus

	return append(vulnerabilities, &vulnObject), nil
}

type falsePositiveFlag struct {
	MechanicalJustification *dtos.MechanicalJustificationType
	Date                    *time.Time
	ProductIDs              gocsaf.Products
}

func calculateVulnStateInformation(ctx context.Context, allVulnsOfCVE []models.DependencyVuln) (*gocsaf.ProductStatus, []falsePositiveFlag, []stateDistributionOfPathsInProduct, gocsaf.Remediations) {
	// build a map for each status type
	affected := map[string]struct{}{}
	notAffected := map[string]struct{}{}
	fixed := map[string]struct{}{}
	underInvestigation := map[string]struct{}{}

	// map each vuln to the leaf product id of its path chain so that decisions are made
	// per exact dependency path rather than per (artifact, component).
	vulnsByProductName := make(map[string][]models.DependencyVuln, len(allVulnsOfCVE))
	for _, vuln := range allVulnsOfCVE {
		path := vulnPath(vuln)
		for _, artifact := range vuln.Artifacts {
			artifactPurl := normalize.Purlify(artifact.ArtifactName, artifact.AssetVersionName)
			key := leafProductID(artifactPurl, path)
			vulnsByProductName[key] = append(vulnsByProductName[key], vuln)
		}
	}

	// build the remediations based off the productNames -> decide the state of the product by analyzing each state of the vulns present
	remediations := []*gocsaf.Remediation{}
	distributions := make([]stateDistributionOfPathsInProduct, 0, len(vulnsByProductName))
	falsePositiveFlags := make([]falsePositiveFlag, 0, len(vulnsByProductName))
	for productName, vulns := range vulnsByProductName {
		distribution := stateDistributionOfPathsInProduct{
			productID:          productName,
			TotalAmountOfPaths: len(vulns),
		}
		acceptedVulns := make([]models.DependencyVuln, 0, len(vulns))
		falsePositiveVulns := make([]models.DependencyVuln, 0, len(vulns))
		fixedVulns := make([]models.DependencyVuln, 0, len(vulns))
		for _, vuln := range vulns {
			switch vuln.State {
			case dtos.VulnStateAccepted:
				acceptedVulns = append(acceptedVulns, vuln)
				distribution.AmountAccepted++
			case dtos.VulnStateFalsePositive:
				falsePositiveVulns = append(falsePositiveVulns, vuln)
				distribution.AmountFalsePositive++
			case dtos.VulnStateFixed:
				// maybe this does not make sense currently
				fixedVulns = append(fixedVulns, vuln)
				distribution.AmountFixed++
			}
		}

		// calculate the amount of unhandled vulns
		distribution.AmountUnhandled = distribution.TotalAmountOfPaths - (distribution.AmountFalsePositive + distribution.AmountAccepted + distribution.AmountFixed)
		distributions = append(distributions, distribution)
		// case: there is an accepted vuln amongst the vulns
		if len(acceptedVulns) > 0 {
			// determine the most recent event and therefore the most recent justification
			justification, _, _ := getMostRecentJustifications(acceptedVulns)
			details := "The risk of this vulnerability has been accepted."
			if justification != nil {
				details += fmt.Sprintf(" Justification: %s", *justification)
			}

			remediations = append(remediations, &gocsaf.Remediation{
				Details:    &details,
				Category:   new(gocsaf.CSAFRemediationCategoryNoFixPlanned),
				ProductIds: new(gocsaf.Products([]*gocsaf.ProductID{new(gocsaf.ProductID(productName))})),
			})

			affected[productName] = struct{}{}
			continue
		}

		// case: all vulns are handled (for this decision we can treat fixed paths as if they weren't existing)
		if len(fixedVulns)+len(falsePositiveVulns) == len(vulns) {
			if len(fixedVulns) == len(vulns) {
				fixed[productName] = struct{}{}
				// nothing to do regarding remediations
				continue
			}

			// else determine the latest justification of the false positive events
			_, mechanicalJustification, date := getMostRecentJustifications(falsePositiveVulns)
			notAffected[productName] = struct{}{}

			// lastly append vuln information to the false positive flags to generate the responsible flag objects later
			falsePositiveFlags = append(falsePositiveFlags, falsePositiveFlag{
				MechanicalJustification: mechanicalJustification,
				Date:                    date,
				ProductIDs:              gocsaf.Products{(*gocsaf.ProductID)(&productName)},
			})

			continue
		}
		underInvestigation[productName] = struct{}{}
	}

	// after putting each vuln in their respective category we build the product status lists with them
	productStatus := &gocsaf.ProductStatus{
		Fixed: emptySliceThenNil(new(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(fixed)), func(el string) *gocsaf.ProductID {
			return new(gocsaf.ProductID(el))
		})))),
		KnownAffected: emptySliceThenNil(new(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(affected)), func(el string) *gocsaf.ProductID {
			return new(gocsaf.ProductID(el))
		})))),
		KnownNotAffected: emptySliceThenNil(new(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(notAffected)), func(el string) *gocsaf.ProductID {
			return new(gocsaf.ProductID(el))
		})))),
		UnderInvestigation: emptySliceThenNil(new(gocsaf.Products(utils.Map(slices.Collect(maps.Keys(underInvestigation)), func(el string) *gocsaf.ProductID {
			return new(gocsaf.ProductID(el))
		})))),
	}
	return productStatus, falsePositiveFlags, distributions, remediations
}

func getMostRecentJustifications(vulns []models.DependencyVuln) (*string, *dtos.MechanicalJustificationType, *time.Time) {
	var latestJustification *string
	var latestMechanicalJustification *dtos.MechanicalJustificationType

	var latestJustificationTimeStamp *time.Time
	var latestMechanicalJustificationTimeStamp *time.Time

	// loop over all vulns and update the 2 latest events variables by using time.Before() if justifications are present
	for _, vuln := range vulns {
		lastEventForVuln := vuln.Events[len(vuln.Events)-1]

		// no justification for this event -> we can skip this one
		if lastEventForVuln.Justification != nil {
			// determine the most recent justification
			if latestJustification == nil {
				latestJustification = lastEventForVuln.Justification
				latestJustificationTimeStamp = &lastEventForVuln.CreatedAt
			} else if latestJustificationTimeStamp.Before(lastEventForVuln.CreatedAt) {
				latestJustification = lastEventForVuln.Justification
				latestJustificationTimeStamp = &lastEventForVuln.CreatedAt
			}
		}

		// do the exact same for mechanical justifications
		if lastEventForVuln.MechanicalJustification != "" {
			if latestMechanicalJustification == nil {
				latestMechanicalJustification = &lastEventForVuln.MechanicalJustification
				latestMechanicalJustificationTimeStamp = &lastEventForVuln.CreatedAt
			} else if latestMechanicalJustificationTimeStamp.Before(lastEventForVuln.CreatedAt) {
				latestMechanicalJustification = &lastEventForVuln.MechanicalJustification
				latestMechanicalJustificationTimeStamp = &lastEventForVuln.CreatedAt
			}
		}
	}

	var timeStamp *time.Time

	if latestJustificationTimeStamp != nil {
		if latestMechanicalJustification != nil && latestJustificationTimeStamp.Before(*latestMechanicalJustificationTimeStamp) {
			timeStamp = latestMechanicalJustificationTimeStamp
		} else {
			timeStamp = latestJustificationTimeStamp
		}
	} else {
		timeStamp = latestMechanicalJustificationTimeStamp
	}

	return latestJustification, latestMechanicalJustification, timeStamp
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

func generateFlagsForVulnerabilityObject(flags []falsePositiveFlag) gocsaf.Flags {
	vulnFlags := make([]*gocsaf.Flag, 0, len(flags))
	for _, flagValues := range flags {
		if flagValues.ProductIDs == nil {
			continue
		}
		if flagValues.MechanicalJustification == nil {
			continue
		}

		// mandatory fields
		flag := gocsaf.Flag{
			ProductIds: &flagValues.ProductIDs,
		}
		flag.Label = (*gocsaf.FlagLabel)(flagValues.MechanicalJustification)

		// optional fields
		if flagValues.Date != nil {
			flag.Date = new(flagValues.Date.Format(time.RFC3339))
		}

		vulnFlags = append(vulnFlags, &flag)
	}
	return vulnFlags
}

// generate the textual summary for a vulnerability object
func generateNotesForVulnerabilityObject(vulns []models.DependencyVuln, distributions []stateDistributionOfPathsInProduct) ([]*gocsaf.Note, error) {
	if len(vulns) == 0 {
		return nil, nil
	}
	notes := []*gocsaf.Note{}

	// always append CVE description note if present
	cve := vulns[0].CVE
	if cve.Description != "" {
		cveDescriptionNote := gocsaf.Note{
			NoteCategory: new(gocsaf.CSAFNoteCategoryDescription),
			Title:        new(fmt.Sprintf("textual description of %s", cve.CVE)),
			Text:         &cve.Description,
		}
		notes = append(notes, &cveDescriptionNote)
	}

	// make a node containing a textual summary for each productID
	for _, distribution := range distributions {
		// build the summary template
		tmpl, err := template.New("build path states").Parse("Total amount of paths in product: {{.TotalAmountOfPaths}}.{{if .AmountAccepted}} Amount of accepted paths: {{.AmountAccepted}}.{{end}}{{if .AmountFalsePositive}} Amount of paths marked as false positives: {{.AmountFalsePositive}}.{{end}}{{if .AmountFixed}} Amount of fixed paths: {{.AmountFixed}}.{{end}}{{if .AmountUnhandled}} Amount of unhandled paths: {{.AmountUnhandled}}.{{end}}")
		if err != nil {
			return nil, fmt.Errorf("could not parse template: %w", err)
		}

		// build the summary for the distribution and assign it to the note object
		var summary strings.Builder
		if err := tmpl.Execute(&summary, distribution); err != nil {
			return nil, fmt.Errorf("could not execute template on distribution: %w", err)
		}

		vulnDetails := gocsaf.Note{
			NoteCategory: new(gocsaf.CSAFNoteCategoryDetails),
			Title:        new(fmt.Sprintf("State of vulnerability paths in product %s", distribution.productID)),
			Text:         new(summary.String()),
		}
		notes = append(notes, &vulnDetails)
	}

	return notes, nil
}

// generate the tracking object used by the document object
func generateTrackingObject(ctx context.Context, vulns []models.DependencyVuln, trackingID *string) (gocsaf.Tracking, error) {
	tracking := gocsaf.Tracking{}

	allEvents := make([]vulnEventWithVuln, 0)
	validEventTypes := []dtos.VulnEventType{dtos.EventTypeDetected, dtos.EventTypeFixed, dtos.EventTypeFalsePositive, dtos.EventTypeAccepted, dtos.EventTypeReopened}
	for _, vuln := range vulns {
		for _, event := range vuln.Events {
			// also filter all events which are not relevant for state lifecycle of the vulnerability
			if slices.Contains(validEventTypes, event.Type) {
				allEvents = append(allEvents, vulnEventWithVuln{
					VulnEvent: event,
					Vuln:      vuln,
				})
			}
		}
	}

	// sort them by their creation timestamp and id to make it deterministic
	slices.SortFunc(allEvents, func(event1 vulnEventWithVuln, event2 vulnEventWithVuln) int {
		timeComp := event1.VulnEvent.CreatedAt.Compare(event2.VulnEvent.CreatedAt)
		if timeComp != 0 {
			return timeComp
		}
		return strings.Compare(event1.Vuln.ID.String(), event2.Vuln.ID.String())
	})

	// then we can construct the full revision history
	revisions, err := buildRevisionHistory(allEvents)
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
	tracking.ID = (*gocsaf.TrackingID)(trackingID)
	tracking.Version = new(gocsaf.RevisionNumber(version))
	tracking.Status = new(gocsaf.CSAFTrackingStatusInterim)

	engineVersion := config.Version
	if engineVersion == "" {
		engineVersion = "debug"
	}
	tracking.Generator = &gocsaf.Generator{
		Engine: &gocsaf.Engine{
			Name:    new("DevGuard CSAF Generator"),
			Version: &engineVersion,
		},
		Date: tracking.CurrentReleaseDate,
	}
	return tracking, nil
}

type vulnEventWithVuln struct {
	VulnEvent models.VulnEvent
	Vuln      models.DependencyVuln
}

// builds the full revision history for an object, that being a list of all changes to all vulnerabilities associated with this asset
func buildRevisionHistory(vulnEvents []vulnEventWithVuln) ([]*gocsaf.Revision, error) {
	var revisions []*gocsaf.Revision

	// combine vulnerability path events which occurred in the same time frame in the same component of the same vuln event type
	// map 1: timestamp _> map 2: component_purl -> map 3: vuln event type -> slice: vulns
	chunkedEventsByTime := make(map[string]map[string]map[dtos.VulnEventType][]vulnEventWithVuln, len(vulnEvents))
	for _, event := range vulnEvents {
		// time.RFC822 truncates timestamp to minutes
		component := event.Vuln.ComponentPurl
		timestamp := event.VulnEvent.CreatedAt.Format(time.RFC822)

		// initialize nested maps on first access to avoid nil map access
		if _, ok := chunkedEventsByTime[timestamp]; !ok {
			chunkedEventsByTime[timestamp] = make(map[string]map[dtos.VulnEventType][]vulnEventWithVuln)
		}
		if _, ok := chunkedEventsByTime[timestamp][component]; !ok {
			chunkedEventsByTime[timestamp][component] = make(map[dtos.VulnEventType][]vulnEventWithVuln)
		}

		chunkedEventsByTime[timestamp][component][event.VulnEvent.Type] = append(chunkedEventsByTime[timestamp][component][event.VulnEvent.Type], event)
	}

	for _, eventsInChunk := range chunkedEventsByTime {
		for component, eventsInComponent := range eventsInChunk {
			for eventType, events := range eventsInComponent {
				// since we grouped by created at timestamp we can just take the first entries timestamp
				var earliestDate *time.Time

				// aggregate all unique artifacts from out vuln selection
				artifactNames := make([]string, 0, len(events))
				for _, event := range events {
					if earliestDate == nil {
						earliestDate = &event.VulnEvent.CreatedAt
					} else if event.VulnEvent.CreatedAt.Before(*earliestDate) {
						earliestDate = &event.VulnEvent.CreatedAt
					}

					for _, artifact := range event.Vuln.Artifacts {
						artifactNames = append(artifactNames, normalize.Purlify(artifact.ArtifactName, artifact.AssetVersionName))
					}
				}

				revisionObject := gocsaf.Revision{
					Date: new((*earliestDate).Format(time.RFC3339)),
				}

				artifactNames = utils.DeduplicateSlice(artifactNames, func(t string) string { return t })
				summary := generateSummaryForEvent(eventType, len(events), component, artifactNames)

				revisionObject.Summary = &summary
				revisions = append(revisions, &revisionObject)
			}
		}
	}

	// sort with higher precision
	slices.SortFunc(revisions, func(revision1, revision2 *gocsaf.Revision) int {
		revision1Timestamp, err := time.Parse(time.RFC3339, *revision1.Date)
		if err != nil {
			return -1
		}

		revision2Timestamp, err := time.Parse(time.RFC3339, *revision2.Date)
		if err != nil {
			return 1
		}
		return revision1Timestamp.Compare(revision2Timestamp)
	})

	version := 1
	for _, entry := range revisions {
		entry.Number = new(gocsaf.RevisionNumber(strconv.Itoa(version)))
		version++
	}
	return revisions, nil
}

func generateSummaryForEvent(eventType dtos.VulnEventType, amountOfEvents int, componentPurl string, artifactNames []string) string {
	artifactNameString := strings.Join(normalize.SortStringsSlice(artifactNames), ", ")

	dynamicPathString := "path"
	dynamicArtifactString := "artifact"

	if amountOfEvents > 1 {
		dynamicPathString = "paths"
	}

	if len(artifactNames) > 1 {
		dynamicArtifactString = "artifacts"
	}

	switch eventType {
	case dtos.EventTypeDetected:
		return fmt.Sprintf("Detected %d %s in package %s (%s: %s)", amountOfEvents, dynamicPathString, componentPurl, dynamicArtifactString, artifactNameString)
	case dtos.EventTypeReopened:
		return fmt.Sprintf("Reopened %d %s in package %s (%s: %s)", amountOfEvents, dynamicPathString, componentPurl, dynamicArtifactString, artifactNameString)
	case dtos.EventTypeFixed:
		return fmt.Sprintf("Fixed %d %s in package %s (%s: %s)", amountOfEvents, dynamicPathString, componentPurl, dynamicArtifactString, artifactNameString)
	case dtos.EventTypeAccepted:
		return fmt.Sprintf("Accepted %d %s in package %s (%s: %s)", amountOfEvents, dynamicPathString, componentPurl, dynamicArtifactString, artifactNameString)
	case dtos.EventTypeFalsePositive:
		return fmt.Sprintf("Marked %d %s as false positive in package %s (%s: %s)", amountOfEvents, dynamicPathString, componentPurl, dynamicArtifactString, artifactNameString)
	}
	return ""
}

// signs report and returns the resulting signature
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

func GenerateDocumentTitle(assetName, cveID string) *string {
	return new(fmt.Sprintf("Security advisory for vulnerability %s in asset %s", cveID, assetName))
}

func (service *csafService) GetOldestVulnPerUniqueCVE(ctx context.Context, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	getOldestVuln := func(leader, newVuln models.DependencyVuln) bool {
		return newVuln.CreatedAt.Before(leader.CreatedAt)
	}

	return service.dependencyVulnService.GetAllUniqueCVEsForAsset(ctx, assetID, getOldestVuln)
}

func (service *csafService) GetAllAdvisories(ctx context.Context, assetID uuid.UUID) ([]models.Advisory, error) {
	return service.advisoryRepository.GetAllAdvisoriesByAssetID(ctx, nil, assetID)
}

func (service csafService) GenerateCSAFReportForAdvisory(ctx context.Context, advisory *models.Advisory, orgName string, assetID uuid.UUID, assetName string) (gocsaf.Advisory, error) {
	csafDoc := gocsaf.Advisory{}

	if len(advisory.AffectedPackages) == 0 {
		return csafDoc, fmt.Errorf("no affected packages found for asset %s", advisory.AssetID)
	}

	cveID := fmt.Sprintf("DGSA-%s", advisory.ID)

	csafDoc.Document = &gocsaf.Document{
		CSAFVersion: new(gocsaf.CSAFVersion20),
		Publisher: &gocsaf.DocumentPublisher{
			Category:  new(gocsaf.CSAFCategoryVendor),
			Name:      &orgName,
			Namespace: new("https://devguard.org"),
		},
		Title: GenerateDocumentTitle(assetName, cveID),
		Lang:  new(gocsaf.Lang("en-US")),
	}

	csafDoc.Document.Distribution = &gocsaf.DocumentDistribution{
		TLP: &gocsaf.TLP{
			DocumentTLPLabel: new(gocsaf.TLPLabel(gocsaf.TLPLabelWhite)),
			URL:              new("https://first.org/tlp"),
		},
	}

	csafDoc.Document.Category = new(gocsaf.DocumentCategory("csaf_security_advisory"))

	tracking, err := generateTrackingObjectForAdvisory(ctx, advisory, assetName, cveID)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.Document.Tracking = &tracking

	tree, err := generateProductTreeForAdvisory(ctx, assetID, advisory.AffectedPackages)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.ProductTree = &tree

	vulnerabilities, err := generateVulnerabilityObjectsForAdvisory(advisory, cveID)
	if err != nil {
		return csafDoc, err
	}
	csafDoc.Vulnerabilities = vulnerabilities

	return csafDoc, nil
}

func generateTrackingObjectForAdvisory(ctx context.Context, advisory *models.Advisory, assetName, cveID string) (gocsaf.Tracking, error) {
	tracking := gocsaf.Tracking{}

	revisions := []*gocsaf.Revision{
		{
			Date:    new(advisory.UpdatedAt.Format(time.RFC3339)),
			Number:  new(gocsaf.RevisionNumber("1")),
			Summary: new(fmt.Sprintf("Security advisory %s published.", cveID)),
		},
	}
	if len(revisions) == 0 {
		return tracking, fmt.Errorf("missing Revision entries")
	}
	tracking.RevisionHistory = revisions

	tracking.InitialReleaseDate = new(advisory.CreatedAt.Format(time.RFC3339))
	tracking.CurrentReleaseDate = revisions[len(revisions)-1].Date

	version := fmt.Sprintf("%d", len(revisions))
	tracking.ID = (*gocsaf.TrackingID)(GenerateDocumentTitle(assetName, cveID))
	tracking.Version = new(gocsaf.RevisionNumber(version))
	tracking.Status = new(gocsaf.CSAFTrackingStatusInterim)

	engineVersion := config.Version
	if engineVersion == "" {
		engineVersion = "debug"
	}
	tracking.Generator = &gocsaf.Generator{
		Engine: &gocsaf.Engine{
			Name:    new("DevGuard CSAF Generator"),
			Version: &engineVersion,
		},
		Date: tracking.CurrentReleaseDate,
	}
	return tracking, nil
}

func generateProductTreeForAdvisory(ctx context.Context, assetID uuid.UUID, affectedPackages []models.AffectedPackage) (gocsaf.ProductTree, error) {
	tree := gocsaf.ProductTree{}

	branches := make(gocsaf.Branches, 0, len(affectedPackages))
	for _, affectedPackage := range affectedPackages {
		vers := versRangeForAffectedPackage(affectedPackage)
		productID := productIDForAffectedPackage(affectedPackage)

		versionRangeBranch := &gocsaf.Branch{
			Category: new(gocsaf.CSAFBranchCategoryProductVersionRange),
			Name:     &vers,
			Product: &gocsaf.FullProductName{
				Name:      new(string(productID)),
				ProductID: new(productID),
			},
		}

		branches = append(branches, &gocsaf.Branch{
			Category: new(gocsaf.CSAFBranchCategoryProductName),
			Name:     new(affectedPackage.PackageName),
			Branches: gocsaf.Branches{versionRangeBranch},
		})
	}

	tree.Branches = branches
	return tree, nil
}

func versRangeForAffectedPackage(ap models.AffectedPackage) string {
	switch {
	case ap.SemverIntroduced != nil && ap.SemverFixed != nil:
		return fmt.Sprintf("vers:%s/>=%s|<%s", ap.Ecosystem, *ap.SemverIntroduced, *ap.SemverFixed)
	case ap.SemverIntroduced != nil:
		return fmt.Sprintf("vers:%s/>=%s", ap.Ecosystem, *ap.SemverIntroduced)
	case ap.SemverFixed != nil:
		return fmt.Sprintf("vers:%s/<%s", ap.Ecosystem, *ap.SemverFixed)
	default:
		return fmt.Sprintf("vers:%s/*", ap.Ecosystem)
	}
}

func productIDForAffectedPackage(ap models.AffectedPackage) gocsaf.ProductID {
	return gocsaf.ProductID(fmt.Sprintf("%s@%s", ap.PackageName, versRangeForAffectedPackage(ap)))
}

func generateVulnerabilityObjectsForAdvisory(advisory *models.Advisory, cveID string) ([]*gocsaf.Vulnerability, error) {
	vulnerabilities := []*gocsaf.Vulnerability{}

	if len(advisory.AffectedPackages) == 0 {
		return vulnerabilities, nil
	}

	vulnObject := gocsaf.Vulnerability{
		IDs:   []*gocsaf.VulnerabilityID{{SystemName: new("DevGuard"), Text: &cveID}},
		Title: &advisory.Title,
	}

	if utils.IsCVE(cveID) {
		vulnObject.CVE = (*gocsaf.CVE)(&cveID)
	}

	notes := gocsaf.Notes{}
	if advisory.Description != "" {
		notes = append(notes, &gocsaf.Note{
			NoteCategory: new(gocsaf.CSAFNoteCategoryDescription),
			Title:        new(fmt.Sprintf("textual description of %s", cveID)),
			Text:         &advisory.Description,
		})
	}

	knownAffected := make(gocsaf.Products, 0, len(advisory.AffectedPackages))
	remediations := gocsaf.Remediations{}
	for _, ap := range advisory.AffectedPackages {
		productID := productIDForAffectedPackage(ap)
		knownAffected = append(knownAffected, new(productID))

		if ap.SemverFixed != nil {
			details := fmt.Sprintf("Upgrade %s to version %s or later.", ap.PackageName, *ap.SemverFixed)
			remediations = append(remediations, &gocsaf.Remediation{
				Category:   new(gocsaf.CSAFRemediationCategoryVendorFix),
				Details:    &details,
				ProductIds: new(gocsaf.Products{new(productID)}),
			})
		}
	}

	vulnObject.Notes = notes
	vulnObject.Remediations = remediations
	vulnObject.ProductStatus = &gocsaf.ProductStatus{KnownAffected: &knownAffected}

	return append(vulnerabilities, &vulnObject), nil
}
