package csaf

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type csaf_controller struct {
	DB                       core.DB
	DependencyVulnRepository core.DependencyVulnRepository
	VulnEventRepository      core.VulnEventRepository
}

// root struct of the document
type csaf struct {
	Document        documentObject  `json:"document,omitempty"`
	ProductTree     productTree     `json:"product_tree,omitempty"`
	Vulnerabilities []vulnerability `json:"vulnerabilities,omitempty"`
}

// ----------MAJOR CATEGORIES----------
// only mandatory parent category
type documentObject struct {
	Acknowledgements  acknowledgements `json:"acknowledgements,omitempty"`
	AggregateSeverity struct {
		Namespace string `json:"namespace,omitempty"`
		Text      string `json:"text,omitempty"`
	} `json:"aggregate_severity,omitempty"`
	Category     string `json:"category,omitempty"`     //mandatory
	CSAFVersion  string `json:"csaf_version,omitempty"` //mandatory
	Distribution struct {
		Text string `json:"text,omitempty"`
		TLP  struct {
			Label string `json:"label,omitempty"`
			URL   string `json:"url,omitempty"`
		} `json:"tlp,omitempty"`
	} `json:"distribution,omitempty"`
	Language       language             `json:"lang,omitempty"`
	Notes          []note               `json:"notes,omitempty"`
	Publisher      publisherReplacement `json:"publisher,omitempty"` //mandatory
	References     []reference          `json:"references,omitempty"`
	SourceLanguage language             `json:"source_lang,omitempty"`
	Title          string               `json:"title,omitempty"` //mandatory
	Tracking       trackingObject       `json:"tracking,omitempty"`
}

type trackingObject struct {
	Aliases            []string `json:"aliases,omitempty"`
	CurrentReleaseDate string   `json:"current_release_date,omitempty"` //mandatory
	Generator          struct {
		Date   string `json:"date,omitempty"`
		Engine struct {
			Name    string `json:"name,omitempty"`
			Version string `json:"version,omitempty"`
		} `json:"engine,omitempty"`
	} `json:"generator,omitempty"`
	ID                 string                `json:"id,omitempty"`                   //mandatory
	InitialReleaseDate string                `json:"initial_release_date,omitempty"` //mandatory
	RevisionHistory    []revisionReplacement `json:"revision_history,omitempty"`
	Status             string                `json:"status,omitempty"`  //mandatory
	Version            version               `json:"version,omitempty"` //mandatory
}

type publisherReplacement struct {
	Category         string `json:"category,omitempty"` //mandatory
	ContactDetails   string `json:"contact_details,omitempty"`
	IssuingAuthority string `json:"issuing_authority,omitempty"`
	Name             string `json:"name,omitempty"`      //mandatory
	Namespace        string `json:"namespace,omitempty"` //mandatory
}

type revisionReplacement struct {
	Date          string  `json:"date,omitempty"` //mandatory
	LegacyVersion string  `json:"legacy_version,omitempty"`
	Number        version //mandatory
	Summary       string  `json:"summary,omitempty"` //mandatory
}

// describe the relation between products (optional)
type productTree struct { //security advisory
	Branches         branches                  `json:"branches,omitempty"`
	FullProductNames []fullProductName         `json:"full_product_name,omitempty"`
	ProductGroups    []productGroupReplacement `json:"product_groups,omitempty"`
	Relationships    []relationshipReplacement `json:"relationships,omitempty"`
}

type productGroupReplacement struct {
	GroupID    productGroupID `json:"group_id,omitempty"`
	ProductIDs []productID    `json:"product_ids,omitempty"`
	Summary    string         `json:"summary,omitempty"`
}

type relationshipReplacement struct {
	Category                  string          `json:"category,omitempty"`
	FullProductName           fullProductName `json:"full_product_name,omitempty"`
	ProductReference          productID       `json:"product_reference,omitempty"`
	RelatesToProductReference productID       `json:"relates_to_product_reference,omitempty"`
}

// describe the vulnerabilities present in products
type vulnerability struct { //security advisory
	Acknowledgements acknowledgements `json:"acknowledgements,omitempty"`
	CVE              string           `json:"cve,omitempty"`
	CWE              struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"cwe,omitempty"`
	DiscoveryDate string            `json:"discovery_date,omitempty"`
	Flags         []flagReplacement `json:"flags,omitempty"`
	IDs           []struct {
		SystemName string `json:"system_name,omitempty"`
		Text       string `json:"text,omitempty"`
	} `json:"ids,omitempty"`
	Involvements  []involvementReplacement `json:"involvements,omitempty"`
	Notes         []note                   `json:"notes,omitempty"` //security advisory
	ProductStatus productStatusReplacement `json:"product_status,omitempty"`
	References    []reference              `json:"references,omitempty"`
	ReleaseDate   string                   `json:"release_date,omitempty"`
	Remediatons   []struct {
		Category        string         `json:"category,omitempty"`
		Date            string         `json:"date,omitempty"`
		Details         string         `json:"details,omitempty"`
		Entitlements    []string       `json:"entitlements,omitempty"`
		GroupIDs        []productGroup `json:"group_ids,omitempty"`
		ProductIDs      products       `json:"product_ids,omitempty"`
		RestartRequired struct {
			Category string `json:"category,omitempty"`
			Details  string `json:"details,omitempty"`
		} `json:"restart_required,omitempty"`
		URL string `json:"url,omitempty"`
	} `json:"remediatons,omitempty"`
	Scores []struct {
		CVSSV2   string   `json:"cvss_v2,omitempty"`
		CVSSV3   string   `json:"cvss_v3,omitempty"`
		Products products `json:"products,omitempty"`
	} `json:"scores,omitempty"`
	Threats []threatReplacement `json:"threats,omitempty"`
	Title   string              `json:"title,omitempty"`
}

type flagReplacement struct {
	Date       string         `json:"date,omitempty"`
	GroupIDs   []productGroup `json:"group_ids,omitempty"`
	Label      string         `json:"label,omitempty"`
	ProductIDs products       `json:"product_ids,omitempty"`
}

type involvementReplacement struct {
	Date    string `json:"date,omitempty"`
	Party   string `json:"party,omitempty"`
	Status  string `json:"status,omitempty"`
	Summary string `json:"summary,omitempty"`
}

type productStatusReplacement struct { //security advisory
	FirstAffected      products `json:"first_affected,omitempty"`
	FirstFixed         products `json:"first_fixed,omitempty"`
	Fixed              products `json:"fixed,omitempty"`
	KnownAffected      products `json:"known_affected,omitempty"`
	KnownNotAffected   products `json:"known_not_affected,omitempty"`
	LastAffected       products `json:"last_affected,omitempty"`
	Recommended        products `json:"recommended,omitempty"`
	UnderInvestigation products `json:"under_investigation,omitempty"`
}

type threatReplacement struct {
	Category   string         `json:"category,omitempty"`
	Date       string         `json:"date,omitempty"`
	Details    string         `json:"details,omitempty"`
	GroupIDs   []productGroup `json:"group_ids,omitempty"`
	ProductIDs products       `json:"product_ids,omitempty"`
}

// ----------TYPE DEFINITIONS----------
type acknowledgements struct {
	Names        []string `json:"names,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	URLS         []string `json:"urls,omitempty"`
}

type branches struct {
	Branches []branches      `json:"branches,omitempty"`
	Category string          `json:"category,omitempty"`
	Name     string          `json:"name,omitempty"`
	Product  fullProductName `json:"product,omitempty"`
}

type fullProductName struct {
	Name                        string                      `json:"name,omitempty"`
	ProductID                   productID                   `json:"product_id,omitempty"`
	ProductIdentificationHelper productIdentificationHelper `json:"product_identification_helper,omitempty"`
}

type productIdentificationHelper struct {
	CPE    string `json:"cpe,omitempty"`
	Hashes []struct {
		FileHashes []struct {
			Algorithm string `json:"algorithm,omitempty"`
			Value     string `json:"value,omitempty"`
		} `json:"file_hashes,omitempty"`
		FileName string `json:"filename,omitempty"`
	} `json:"hashes,omitempty"`
	ModelNumbers []string `json:"model_numbers,omitempty"`
	PURL         string   `json:"purl,omitempty"`
	SBOMURLS     []string `json:"sbom_urls,omitempty"`
	SKUS         []string `json:"skus,omitempty"`
	//generic uris...
}

type language = string

type note struct {
	Audience string `json:"audience,omitempty"`
	Category string `json:"category,omitempty"`
	Text     string `json:"text,omitempty"`
	Title    string `json:"title,omitempty"`
}

type productGroupID = string

type productGroup = []productGroupID

type products = []productID

type reference struct {
	Category string `json:"category,omitempty"`
	Summary  string `json:"summary,omitempty"`
	URL      string `json:"url,omitempty"`
}

type version = string

type productID = string

func NewCSAFController(db core.DB, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository) *csaf_controller {
	return &csaf_controller{
		DB:                       db,
		DependencyVulnRepository: dependencyVulnRepository,
		VulnEventRepository:      vulnEventRepository,
	}
}

func (controller *csaf_controller) GenerateCSAFReport(ctx core.Context) error {
	slog.Info("start generating CSAF Document")
	csafDoc := csaf{}
	artifact := core.GetArtifact(ctx)
	org := core.GetOrg(ctx)
	csafDoc.Document = documentObject{
		Category:    "csaf_security_advisory",
		CSAFVersion: "2.0",
		Publisher: publisherReplacement{
			Category:  "vendor",
			Name:      org.Slug,
			Namespace: "https://l3montree.com", // TODO
		},
		Title: "Dependency Vulnerabilities present in the software",
	}
	tracking, err := generateTrackingObject(artifact, controller.DependencyVulnRepository, controller.VulnEventRepository)
	if err != nil {
		return err
	}
	csafDoc.Document.Tracking = tracking
	fd, err := os.Create(csafDoc.Document.Title)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(fd)
	err = encoder.Encode(csafDoc)
	if err != nil {
		return err
	}
	slog.Info("successfully generated CSAF Document")
	return nil
}

func generateVulnerabilitiesObject(artifact models.Artifact, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository) ([]vulnerability, error) {
	vulns, err := dependencyVulnRepository.GetAllVulnsByArtifact(nil, artifact)
	if err != nil {
		return nil, err
	}
	var vulnerabilites []vulnerability
	for _, vuln := range vulns {
		vulnObject := vulnerability{}
		events, err := vulnEventRepository.ReadAssetEventsByVulnID(vuln.ID, models.VulnTypeDependencyVuln)
		if err != nil {
			return nil, err
		}
		vulnObject.CVE = *vuln.CVEID
		vulnObject.DiscoveryDate = events[0].CreatedAt.String()
		vulnerabilites = append(vulnerabilites, vulnObject)
	}
	return vulnerabilites, nil
}

func generateTrackingObject(artifact models.Artifact, dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository) (trackingObject, error) {
	tracking := trackingObject{}
	vulns, err := dependencyVulnRepository.GetAllVulnsByArtifact(nil, artifact)
	if err != nil {
		return tracking, err
	}
	allEvents := make([]models.VulnEventDetail, 0, len(vulns))
	for _, vuln := range vulns {
		events, err := vulnEventRepository.ReadAssetEventsByVulnID(vuln.ID, models.VulnTypeDependencyVuln)
		if err != nil {
			return tracking, err
		}
		allEvents = append(allEvents, events...)
	}
	slices.SortFunc(allEvents, func(event1 models.VulnEventDetail, event2 models.VulnEventDetail) int {
		return event1.CreatedAt.Compare(event2.CreatedAt)
	})

	version := fmt.Sprintf("version %d", len(allEvents))
	tracking.ID = fmt.Sprintf("csaf_report_%s_%s", artifact.ArtifactName, version)
	tracking.Version = version
	tracking.InitialReleaseDate = allEvents[0].CreatedAt.String()
	tracking.CurrentReleaseDate = allEvents[len(allEvents)-1].CreatedAt.String()
	revisions, err := buildRevisionHistory(allEvents)
	if err != nil {
		return tracking, err
	}
	tracking.RevisionHistory = revisions

	return tracking, nil
}

func buildRevisionHistory(events []models.VulnEventDetail) ([]revisionReplacement, error) {
	var revisions []revisionReplacement
	for i, event := range events {
		revisionObject := revisionReplacement{
			Date: event.CreatedAt.String(),
		}
		switch event.Type {
		case models.EventTypeDetected:
			revisionObject.Summary = fmt.Sprintf("Detected new vulnerability (CVE:%s)", event.CVEID)
		case models.EventTypeFixed:
			revisionObject.Summary = fmt.Sprintf("Fixed Vulnerability (CVE:%s)", event.CVEID)
		case models.EventTypeMitigate:
			revisionObject.Summary = fmt.Sprintf("Mitigated Vulnerability (CVE:%s)", event.CVEID)
		}
		revisionObject.Number = strconv.Itoa(i)
		revisions = append(revisions, revisionObject)
	}
	return revisions, nil
}
