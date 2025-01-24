package vulndb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"

	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

type cvesRepository interface {
	repositories.Repository[string, models.CVE, database.DB]
	GetAllCVEsID() ([]string, error)
	GetAllCPEMatchesID() ([]string, error)
	Save(tx database.DB, cve *models.CVE) error
	SaveBatchCPEMatch(tx database.DB, matches []models.CPEMatch) error
	SaveCveAffectedComponents(tx core.DB, cveId string, affectedComponentHashes []string) error
}
type cwesRepository interface {
	GetAllCWEsID() ([]string, error)
	SaveBatch(tx database.DB, cwes []models.CWE) error
}

type exploitsRepository interface {
	GetAllExploitsID() ([]string, error)
	SaveBatch(tx core.DB, exploits []models.Exploit) error
}

type affectedComponentsRepository interface {
	GetAllAffectedComponentsID() ([]string, error)
	Save(tx database.DB, affectedComponent *models.AffectedComponent) error
	SaveBatch(tx core.DB, affectedPkgs []models.AffectedComponent) error
}
type importService struct {
	cveRepository                cvesRepository
	cweRepository                cwesRepository
	exploitRepository            exploitsRepository
	affectedComponentsRepository affectedComponentsRepository
}

type configService interface {
	GetJSONConfig(key string, v any) error
	SetJSONConfig(key string, v any) error
}

type leaderElector interface {
	IfLeader(ctx context.Context, fn func() error)
}

func StartMirror(db core.DB, leaderElector leaderElector, configService configService) {
	cveRepository := repositories.NewCVERepository(db)
	cweRepository := repositories.NewCWERepository(db)
	exploitsRepository := repositories.NewExploitRepository(db)
	affectedComponentsRepository := repositories.NewAffectedComponentRepository(db)

	v := NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository)
	leaderElector.IfLeader(context.Background(), func() error {
		var lastMirror struct {
			Time time.Time `json:"time"`
		}

		err := configService.GetJSONConfig("vulndb.lastMirror", &lastMirror)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			slog.Error("could not get last mirror time", "err", err)
			return nil
		} else if errors.Is(err, gorm.ErrRecordNotFound) {
			slog.Info("no last mirror time found. Setting to 0")
			lastMirror.Time = time.Time{}
		}

		if time.Since(lastMirror.Time) > 2*time.Hour {
			slog.Info("last mirror was more than 2 hours ago. Starting mirror process")

			if err := v.Import(db, "latest"); err != nil {
				slog.Error("could not import vulndb", "err", err)
			}
		} else {
			slog.Info("last mirror was less than 2 hours ago. Not mirroring", "lastMirror", lastMirror.Time, "now", time.Now())
		}
		slog.Info("done. Waiting for 2 hours to check again")
		time.Sleep(2 * time.Hour)
		return nil
	})
}

func NewImportService(cvesRepository cvesRepository, cweRepository cwesRepository, exploitRepository exploitsRepository, affectedComponentsRepository affectedComponentsRepository) *importService {
	return &importService{
		cveRepository:                cvesRepository,
		cweRepository:                cweRepository,
		exploitRepository:            exploitRepository,
		affectedComponentsRepository: affectedComponentsRepository,
	}
}

func (s importService) Import(tx database.DB, tag string) error {
	slog.Info("Importing vulndb started")
	begin := time.Now()
	tmp := "./vulndb-tmp"
	sigFile := tmp + "/vulndb.zip.sig"
	blobFile := tmp + "/vulndb.zip"
	pubKeyFile := "cosign.pub"

	ctx := context.Background()

	reg := "ghcr.io/l3montree-dev/devguard/vulndb"

	// create a file store
	defer os.RemoveAll(tmp)
	fs, err := file.New(tmp)
	if err != nil {
		panic(err)
	}
	defer fs.Close()

	//import the vulndb csv to the file store
	err = copyCSVFromRemoteToLocal(ctx, reg, tag, fs)
	if err != nil {
		return fmt.Errorf("could not copy csv from remote to local: %w", err)
	}

	// verify the signature of the imported data
	err = verifySignature(pubKeyFile, sigFile, blobFile, ctx)
	if err != nil {
		return fmt.Errorf("could not verify signature: %w", err)
	}
	slog.Info("successfully verified signature")

	// open the blob file
	f, err := os.Open(blobFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Unzip the blob file
	err = utils.Unzip(blobFile, tmp+"/")
	if err != nil {
		panic(err)
	}
	slog.Info("Unzipping vulndb completed")

	//copy csv files to database
	err = s.copyCSVToDB(tx, tmp)
	if err != nil {
		return err
	}

	slog.Info("Importing vulndb completed", "duration", time.Since(begin))

	return nil
}

func readCSVFile(f *os.File) *csv.Reader {
	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1 // Allow variable number of fields
	return reader
}

func (s importService) importCves(tx database.DB, f *os.File) error {
	slog.Info("Importing cves started")
	begin := time.Now()
	// Read cves.csv
	reader := readCSVFile(f)

	// Get all existing cve ids in the database
	cvesID, err := s.cveRepository.GetAllCVEsID()
	if err != nil {
		return err
	}

	// Skip the header
	reader.Read()

	// csv to model and save
	amountRead, err := s.modelAndSaveCve(tx, reader)
	if err != nil {
		return err
	}

	amountOfCves := amountRead
	amountOfOldCves := len(cvesID)

	slog.Info("finished importing cves", "amountOfCves", amountOfCves, "amountOfOldCves", amountOfOldCves, "amountOfOldCvesNotInNewImportedList", amountOfOldCves-amountOfCves, "duration", time.Since(begin))
	return nil
}

func (s importService) modelAndSaveCve(tx database.DB, reader *csv.Reader) (int, error) {
	return utils.ReadCsvInChunks(reader, 100, func(rows [][]string) error {
		cves := utils.Map(rows, func(row []string) models.CVE {
			model, _ := csvRowToCveModel(row)
			return model
		})
		return s.cveRepository.SaveBatch(tx, cves)
	})
}

func csvRowToCveModel(row []string) (models.CVE, error) {
	var cve models.CVE

	createdAt := time.Time{}
	if row[1] != "" {
		c, err := time.Parse("2006-01-02 15:04:05.999999-07", row[1])
		if err != nil {
			return cve, err
		}
		createdAt = c
	}
	updatedAt := time.Time{}
	if row[2] != "" {
		u, err := time.Parse("2006-01-02 15:04:05.999999-07", row[2])
		if err != nil {
			return cve, err
		}
		updatedAt = u
	}

	datePublished := time.Time{}
	if row[3] != "" {
		d, err := time.Parse("2006-01-02 15:04:05.999999-07", row[3])
		if err != nil {
			return cve, err
		}
		datePublished = d
	}

	dateLastModified := time.Time{}
	if row[4] != "" {
		d, err := time.Parse("2006-01-02 15:04:05.999999-07", row[4])
		if err != nil {
			return cve, err
		}
		dateLastModified = d
	}

	cvss := float64(0)
	if row[6] != "" {
		c, err := strconv.ParseFloat(row[6], 32)
		if err != nil {
			return cve, err
		}
		cvss = c
	}

	severity := models.Severity(row[7])

	exploitabilityScore := float64(0)
	if row[8] != "" {
		e, err := strconv.ParseFloat(row[8], 32)
		if err != nil {
			return cve, err
		}
		exploitabilityScore = e
	}

	impactScore := float64(0)
	if row[9] != "" {
		i, err := strconv.ParseFloat(row[9], 32)
		if err != nil {
			return cve, err
		}
		impactScore = i
	}

	var cisaExploitAdd *datatypes.Date = nil
	if row[19] != "" {
		cISAExploitAddTime, err := time.Parse("2006-01-02", row[19])
		if err != nil {
			return cve, fmt.Errorf("error parsing cisa exploit add time: %w", err)
		}
		cisaExploitAdd = utils.Ptr(datatypes.Date(cISAExploitAddTime))
	}

	var cisaActionDue *datatypes.Date = nil
	if row[20] != "" {
		cisaActionDueTime, err := time.Parse("2006-01-02", row[20])
		if err != nil {
			return cve, fmt.Errorf("error parsing cisa action due time: %w", err)
		}

		cisaActionDue = utils.Ptr(datatypes.Date(cisaActionDueTime))
	}

	epss := float64(0)
	if row[23] != "" {
		e, err := strconv.ParseFloat(row[23], 64)
		if err != nil {
			return cve, err
		}
		epss = e
	}

	percentile64 := float64(0)
	if row[24] != "" {
		p, err := strconv.ParseFloat(row[24], 32)
		if err != nil {
			return cve, err
		}
		percentile64 = p
	}
	percentile := float32(percentile64)

	cve = models.CVE{
		CVE:                   row[0],
		CreatedAt:             createdAt,
		UpdatedAt:             updatedAt,
		DatePublished:         datePublished,
		DateLastModified:      dateLastModified,
		Description:           row[5],
		CVSS:                  float32(cvss),
		Severity:              severity,
		ExploitabilityScore:   float32(exploitabilityScore),
		ImpactScore:           float32(impactScore),
		AttackVector:          row[10],
		AttackComplexity:      row[11],
		PrivilegesRequired:    row[12],
		UserInteraction:       row[13],
		Scope:                 row[14],
		ConfidentialityImpact: row[15],
		IntegrityImpact:       row[16],
		AvailabilityImpact:    row[17],
		References:            row[18],
		CISAExploitAdd:        cisaExploitAdd,
		CISAActionDue:         cisaActionDue,
		CISARequiredAction:    row[21],
		CISAVulnerabilityName: row[22],
		EPSS:                  &epss,
		Percentile:            &percentile,
		Vector:                row[25],
	}

	return cve, nil
}

// import cpe_matches
func (s importService) importCpeMatches(tx database.DB, f *os.File) error {
	slog.Info("Importing cpe_matches started")
	begin := time.Now()
	// Read cpe_matches.csv
	reader := readCSVFile(f)

	// Get all existing cpesID in the database
	cpeMatchesID, err := s.cveRepository.GetAllCPEMatchesID()
	if err != nil {
		return err
	}

	// Skip the header
	reader.Read()
	// model and save
	amountRead, err := s.modelAndSaveCpeMatch(tx, reader)
	if err != nil {
		return err
	}

	slog.Info("finished importing cpe_matches", "amountOfCpeMatches", amountRead, "amountOfOldCpeMatches", len(cpeMatchesID), "duration", time.Since(begin))

	return nil
}

func (s importService) modelAndSaveCpeMatch(tx database.DB, reader *csv.Reader) (int, error) {
	return utils.ReadCsvInChunks(reader, 100, func(rows [][]string) error {
		models := utils.Map(rows, func(row []string) models.CPEMatch {
			model, _ := csvRowToCpeMatchModel(row)
			return model
		})
		return s.cveRepository.SaveBatchCPEMatch(tx, models)
	})
}

func csvRowToCpeMatchModel(row []string) (models.CPEMatch, error) {
	vulnerable, err := strconv.ParseBool(row[17])
	if err != nil {
		return models.CPEMatch{}, err
	}
	cpeMatch := models.CPEMatch{
		MatchCriteriaID:       row[0],
		Criteria:              row[1],
		Part:                  row[2],
		Vendor:                row[3],
		Product:               row[4],
		Update:                row[5],
		Edition:               row[6],
		Language:              row[7],
		SwEdition:             row[8],
		TargetSw:              row[9],
		TargetHw:              row[10],
		Other:                 row[11],
		Version:               row[12],
		VersionEndExcluding:   &row[13],
		VersionEndIncluding:   &row[14],
		VersionStartIncluding: &row[15],
		VersionStartExcluding: &row[16],
		Vulnerable:            vulnerable,
	}
	return cpeMatch, nil
}

// import cwe
func (s importService) importCwes(tx database.DB, f *os.File) error {
	slog.Info("Importing cwes started")
	begin := time.Now()
	// Read cwes.csv
	reader := readCSVFile(f)

	// Get all existing cwesID in the database
	cwesID, err := s.cweRepository.GetAllCWEsID()
	if err != nil {
		return err
	}

	// Skip the header
	reader.Read()
	// model and save
	amountRead, err := s.modelAndSaveCwe(tx, reader)
	if err != nil {
		return err
	}

	slog.Info("finished importing cwes", "amountOfCwes", amountRead, "amountOfOldCwes", len(cwesID), "duration", time.Since(begin))
	return nil
}

func (s importService) modelAndSaveCwe(tx database.DB, reader *csv.Reader) (int, error) {
	return utils.ReadCsvInChunks(reader, 100, func(rows [][]string) error {
		models := utils.Map(rows, func(row []string) models.CWE {
			model, _ := csvRowToCweModel(row)
			return model
		})
		return s.cweRepository.SaveBatch(tx, models)
	})
}

func csvRowToCweModel(row []string) (models.CWE, error) {
	var cwe models.CWE
	createdAt, err := time.Parse("2006-01-02 15:04:05.999999-07", row[0])
	if err != nil {
		return cwe, err
	}
	updatedAt, err := time.Parse("2006-01-02 15:04:05.999999-07", row[1])
	if err != nil {
		return cwe, err
	}

	/*
		deletedAt, err := time.Parse("2006-01-02 15:04:05.999999-07", row[2])
		if err != nil {
			return cwe, err
		}
	*/

	cwe = models.CWE{
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		//TODO
		//DeletedAt:   deletedAt,
		CWE:         row[3],
		Description: row[4],
	}

	return cwe, nil
}

// import exploits
func (s importService) importExploits(tx database.DB, f *os.File) error {
	slog.Info("Importing exploits started")
	begin := time.Now()
	// Read exploits.csv
	reader := readCSVFile(f)

	// Get all existing exploitsID in the database
	exploitsID, err := s.exploitRepository.GetAllExploitsID()
	if err != nil {
		return err
	}

	// Skip the header
	reader.Read()
	// Save all exploits
	amountRead, err := s.modelAndSaveExploit(tx, reader)
	if err != nil {
		return err
	}

	slog.Info("finished importing exploits", "amountOfExploits", amountRead, "amountOfOldExploits", len(exploitsID), "duration", time.Since(begin))

	return nil
}
func (s importService) modelAndSaveExploit(tx database.DB, reader *csv.Reader) (int, error) {
	return utils.ReadCsvInChunks(reader, 100, func(rows [][]string) error {
		exploits := utils.Map(rows, func(row []string) models.Exploit {
			model, _ := csvRowToExploitModel(row)
			return model
		})
		return s.exploitRepository.SaveBatch(tx, exploits)
	})
}

func csvRowToExploitModel(row []string) (models.Exploit, error) {
	var exploit models.Exploit

	published := time.Time{}
	if row[1] != "" {
		p, err := time.Parse("2006-01-02", row[1])
		if err != nil {
			return exploit, err
		}
		published = p
	}
	updated := time.Time{}
	if row[2] != "" {
		u, err := time.Parse("2006-01-02", row[2])
		if err != nil {
			return exploit, err
		}
		updated = u
	}

	verified, err := strconv.ParseBool(row[5])
	if err != nil {
		return exploit, err
	}

	forks := 0
	if row[10] != "" {
		f, err := strconv.Atoi(row[10])
		if err != nil {
			return exploit, err
		}

		forks = f
	}
	watchers := 0
	if row[11] != "" {
		w, err := strconv.Atoi(row[11])
		if err != nil {
			return exploit, err
		}
		watchers = w
	}
	subscribers := 0
	if row[12] != "" {
		s, err := strconv.Atoi(row[12])
		if err != nil {
			return exploit, err
		}
		subscribers = s
	}
	stars := 0
	if row[13] != "" {
		s, err := strconv.Atoi(row[13])
		if err != nil {
			return exploit, err
		}
		stars = s
	}

	exploit = models.Exploit{
		ID:          row[0],
		Published:   &published,
		Updated:     &updated,
		Author:      row[3],
		Type:        row[4],
		Verified:    verified,
		SourceURL:   row[6],
		Description: row[7],
		CVEID:       row[8],
		Tags:        row[9],
		Forks:       forks,
		Watchers:    watchers,
		Subscribers: subscribers,
		Stars:       stars,
	}

	return exploit, nil
}

// import affected_components
func (s importService) importAffectedComponents(tx database.DB, f *os.File) error {
	slog.Info("Importing affected_components started")
	begin := time.Now()
	// Read affected_components.csv
	reader := readCSVFile(f)

	// Get all existing affectedComponentsID in the database
	affectedComponentsID, err := s.affectedComponentsRepository.GetAllAffectedComponentsID()
	if err != nil {
		return err
	}

	// Skip the header
	reader.Read()
	// model and save
	amountRead, err := s.modelAndSaveAffectedComponent(tx, reader)
	if err != nil {
		return err
	}

	slog.Info("finished importing affected_components", "amountOfAffectedComponents", amountRead, "amountOfOldAffectedComponents", len(affectedComponentsID), "duration", time.Since(begin))

	return nil
}

func (s importService) modelAndSaveAffectedComponent(tx database.DB, reader *csv.Reader) (int, error) {
	return utils.ReadCsvInChunks(reader, 100, func(rows [][]string) error {
		affectedComponents := utils.Map(rows, func(row []string) models.AffectedComponent {
			model, _ := CsvRowToAffectedComponentModel(row)
			return model
		})

		return s.affectedComponentsRepository.SaveBatch(tx, affectedComponents)
	})
}

func CsvRowToAffectedComponentModel(row []string) (models.AffectedComponent, error) {
	var semverIntroduced *string
	if row[11] != "" {
		semverIntroduced = &row[11]
	}
	var semverFixed *string
	if row[12] != "" {
		semverFixed = &row[12]
	}

	affectedComponent := models.AffectedComponent{
		ID:                row[0],
		Source:            row[1],
		PURL:              row[2],
		Ecosystem:         row[3],
		Scheme:            row[4],
		Type:              row[5],
		Name:              row[6],
		Namespace:         &row[7],
		Qualifiers:        &row[8],
		Subpath:           &row[9],
		Version:           &row[10],
		SemverIntroduced:  semverIntroduced,
		SemverFixed:       semverFixed,
		VersionIntroduced: &row[13],
		VersionFixed:      &row[14],
	}
	return affectedComponent, nil
}

// import weaknesses
func (s importService) importWeaknesses(tx database.DB, f *os.File) error {
	slog.Info("Importing weaknesses started")
	begin := time.Now()
	// Read weaknesses.csv
	reader := readCSVFile(f)
	// Skip the header
	reader.Read()
	// model and save
	amountRead, err := s.modelAndSaveWeaknesses(reader)
	if err != nil {
		return err
	}
	amountOfWeaknesses := amountRead

	slog.Info("finished importing weaknesses", "amountOfWeaknesses", amountOfWeaknesses, "duration", time.Since(begin))
	return nil
}

func (s importService) modelAndSaveWeaknesses(reader *csv.Reader) (int, error) {
	return utils.ReadCsvInChunks(reader, 100, func(rows [][]string) error {
		weaknesses := utils.Map(rows, func(row []string) models.Weakness {
			model, _ := csvRowToWeaknessModel(row)
			return model
		})

		return s.saveWeaknesses(nil, weaknesses)
	})
}

func groupWeaknessesByCVE(weaknesses []models.Weakness) map[string][]models.Weakness {
	weaknessesByCVE := make(map[string][]models.Weakness)
	for _, weakness := range weaknesses {
		weaknessesByCVE[weakness.CVEID] = append(weaknessesByCVE[weakness.CVEID], weakness)
	}
	return weaknessesByCVE
}

func (s importService) saveWeaknesses(tx database.DB, weaknesses []models.Weakness) error {
	// Group weaknesses by cveID
	weaknessesByCVE := groupWeaknessesByCVE(weaknesses)

	for cveId, weaknessesGroup := range weaknessesByCVE {
		// add weaknesses to the cve
		if err := s.cveRepository.GetDB(tx).Model(&models.CVE{
			CVE: cveId,
		}).Association("Weaknesses").Append(utils.Map(weaknessesGroup, func(w models.Weakness) models.Weakness {
			return models.Weakness{
				Source: w.Source,
				Type:   w.Type,
				CVEID:  cveId,
				CWEID:  w.CWEID,
			}
		})); err != nil {
			return err
		}
	}
	return nil
}
func csvRowToWeaknessModel(row []string) (models.Weakness, error) {
	return models.Weakness{
		Source: row[0],
		Type:   row[1],
		CVEID:  row[2],
		CWEID:  row[3],
	}, nil
}

// import cpe_cve_matches
func (s importService) importCveCpeMatches(tx database.DB, f *os.File) error {
	slog.Info("Importing cpe_cve_matches started")
	begin := time.Now()
	// Read cpe_cve_matches.csv
	reader := readCSVFile(f)

	// Skip the header
	reader.Read()

	// Save all cpe_cve_matches
	amountRead, err := s.saveCpeCveMatches(tx, reader)
	if err != nil {
		return err
	}

	slog.Info("finished importing cpe_cve_matches", "amountOfCpeCveMatches", amountRead, "duration", time.Since(begin))
	return nil
}
func (s importService) saveCpeCveMatches(tx database.DB, csvData *csv.Reader) (int, error) {
	return utils.ReadCsvInChunks(csvData, 100, func(rows [][]string) error {
		//Group cpeCveMatches by cveID
		cpeCveMatchesByCVE := groupCpeCveMatchesByCVE(rows)
		return s.saveCpeCveMatchesGroup(tx, cpeCveMatchesByCVE)
	})
}
func groupCpeCveMatchesByCVE(csvData [][]string) map[string][]string {
	// the key will be the cve id. The value will be an array of cpe match criteria ids
	cveToCpeMatches := make(map[string][]string)
	for _, row := range csvData {
		criteriaID := row[0]
		cveId := row[1]
		if _, ok := cveToCpeMatches[cveId]; !ok {
			// we do not have any cpe matches for this cve yet
			cveToCpeMatches[cveId] = []string{}
		}
		cveToCpeMatches[cveId] = append(cveToCpeMatches[cveId], criteriaID)
	}
	return cveToCpeMatches
}
func (s importService) saveCpeCveMatchesGroup(tx database.DB, cpeMatchesByCVE map[string][]string) error {
	for cveId, cpeMatches := range cpeMatchesByCVE {
		for i := 0; i < len(cpeMatches); i += 1000 {
			end := i + 1000
			if end > len(cpeMatches) {
				end = len(cpeMatches)
			}
			// add cpeCveMatches to the cve
			if err := s.cveRepository.GetDB(tx).Session(&gorm.Session{
				// disable logging
				// it might log slow queries or a missing cve.
				Logger: logger.Default.LogMode(logger.Silent),
			}).Model(&models.CVE{
				CVE: cveId,
			}).Association("Configurations").Append(utils.Map(utils.UniqBy(cpeMatches[i:end], func(c string) string {
				return c
			}), func(c string) models.CPEMatch {
				return models.CPEMatch{
					MatchCriteriaID: c,
				}
			})); err != nil {
				return fmt.Errorf("error saving cpe_cve_matches: %w", err)
			}
		}
	}
	return nil
}

// import cve_affects_component
func (s importService) importCveAffectedComponent(tx database.DB, f *os.File) error {
	slog.Info("Importing cve_affects_component started")
	begin := time.Now()
	// Read cve_affects_component.csv
	reader := readCSVFile(f)

	// Skip the header
	reader.Read()
	// model and save
	amountRead, err := s.saveCveAffectedComponents(tx, reader)
	if err != nil {
		return err
	}

	slog.Info("finished importing cve_affects_component", "amountOfCveAffectedComponents", amountRead, "duration", time.Since(begin))

	return nil
}
func (s importService) saveCveAffectedComponents(tx database.DB, reader *csv.Reader) (int, error) {

	return utils.ReadCsvInChunks(reader, 100, func(rows [][]string) error {
		// model and save
		//Group affectedComponents by cveID
		cveToAffectedComponents := groupAffectedComponentsByCVE(rows)
		return s.saveCveAffectedComponentsGroup(tx, cveToAffectedComponents)
	})
}

func groupAffectedComponentsByCVE(csvData [][]string) map[string][]string {
	// the key will be the cve id. The value will be an array of cpe match criteria ids
	cveToAffectedComponents := make(map[string][]string)
	for _, row := range csvData {
		if len(row) < 2 {
			continue
		}
		affectedComponentHash := row[0]
		cveId := row[1]
		if _, ok := cveToAffectedComponents[cveId]; !ok {
			// we do not have any cpe matches for this cve yet
			cveToAffectedComponents[cveId] = []string{}
		}
		cveToAffectedComponents[cveId] = append(cveToAffectedComponents[cveId], affectedComponentHash)
	}
	return cveToAffectedComponents
}

func (s importService) saveCveAffectedComponentsGroup(tx database.DB, cveToAffectedComponents map[string][]string) error {
	for cveId, affectedComponentHashes := range cveToAffectedComponents {
		for i := 0; i < len(affectedComponentHashes); i += 1000 {
			end := i + 1000
			if end > len(affectedComponentHashes) {
				end = len(affectedComponentHashes)
			}
			// add cpeCveMatches to the cve
			if err := s.cveRepository.SaveCveAffectedComponents(tx, cveId, utils.UniqBy(affectedComponentHashes[i:end], func(c string) string {
				return c
			})); err != nil {
				return fmt.Errorf("error saving cve_affected_components: %w", err)
			}
		}
	}
	return nil
}

func (s importService) copyCSVToDB(tx database.DB, tmp string) error {

	// Import cves
	cvesCsv, err := os.Open(tmp + "/" + "cves.csv")
	if err != nil {
		panic(err)
	}
	defer cvesCsv.Close()
	err = s.importCves(tx, cvesCsv)
	if err != nil {
		return err
	}
	slog.Info("Importing cves done")

	// Import cpe_matches
	cpeMatchesCsv, err := os.Open(tmp + "/" + "cpe_matches.csv")
	if err != nil {
		panic(err)
	}
	defer cpeMatchesCsv.Close()
	err = s.importCpeMatches(tx, cpeMatchesCsv)
	if err != nil {
		return err
	}
	slog.Info("Importing cpe_matches done")

	// Import cwes
	cwesCsv, err := os.Open(tmp + "/" + "cwes.csv")
	if err != nil {
		panic(err)
	}
	defer cwesCsv.Close()
	err = s.importCwes(tx, cwesCsv)
	if err != nil {
		return err
	}
	slog.Info("Importing cwes done")

	// Import Exploits
	exploitsCsv, err := os.Open(tmp + "/" + "exploits.csv")
	if err != nil {
		panic(err)
	}
	defer exploitsCsv.Close()
	err = s.importExploits(tx, exploitsCsv)
	if err != nil {
		return err
	}
	slog.Info("Importing vulndb done")

	//import affected_components
	affectedCmpCsv, err := os.Open(tmp + "/" + "affected_component.csv")
	if err != nil {
		panic(err)
	}
	defer affectedCmpCsv.Close()
	err = s.importAffectedComponents(tx, affectedCmpCsv)
	if err != nil {
		return err
	}
	slog.Info("Importing affected_components done")

	// import weaknesses
	weaknessesCsv, err := os.Open(tmp + "/" + "weaknesses.csv")
	if err != nil {
		panic(err)
	}
	defer weaknessesCsv.Close()
	err = s.importWeaknesses(tx, weaknessesCsv)
	if err != nil {
		return err
	}
	slog.Info("Importing weaknesses done")

	// import cpe_cve_matches
	cpeCveMatchesCsv, err := os.Open(tmp + "/" + "cve_cpe_match.csv")
	if err != nil {
		panic(err)
	}
	defer cpeCveMatchesCsv.Close()
	err = s.importCveCpeMatches(tx, cpeCveMatchesCsv)
	if err != nil {
		return err
	}
	slog.Info("Importing cpe_cve_matches done")

	//import cve_affects_component
	cveAffectsComponentCsv, err := os.Open(tmp + "/" + "cve_affected_component.csv")
	if err != nil {
		panic(err)
	}
	defer cveAffectsComponentCsv.Close()
	err = s.importCveAffectedComponent(tx, cveAffectsComponentCsv)
	if err != nil {
		return err
	}
	return nil

}

func verifySignature(pubKeyFile string, sigFile string, blobFile string, ctx context.Context) error {
	// Load the public key
	pubKeyData, err := os.ReadFile(pubKeyFile)
	if err != nil {
		return fmt.Errorf("could not read public key: %w", err)
	}

	// PEM-Block dekodieren
	block, _ := pem.Decode(pubKeyData)
	if block == nil {
		return fmt.Errorf("could not decode pem block")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("could not parse public key: %w", err)
	}

	// ECDSA-key generation
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to parse public key")
	}

	// Load the signature file
	sigFileData, err := os.ReadFile(sigFile)
	if err != nil {
		return fmt.Errorf("could not read signature file: %w", err)
	}

	// decode base64 signature
	base64Sig := string(sigFileData)
	sig, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		return fmt.Errorf("could not decode base64 signature: %w", err)
	}

	// load the block using a reader
	file, err := os.Open(blobFile)
	if err != nil {
		return fmt.Errorf("could not read blob file: %w", err)
	}

	// setup verifier
	verifier, err := signature.LoadECDSAVerifier(ecdsaPubKey, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("could not load verifier: %w", err)
	}

	// Verify the signature
	err = verifier.VerifySignature(bytes.NewReader(sig), file, options.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("could not verify signature: %w", err)
	}

	return nil
}
func copyCSVFromRemoteToLocal(ctx context.Context, reg string, tag string, fs *file.Store) error {
	// Connect to a remote repository
	repo, err := remote.NewRepository(reg)
	if err != nil {
		return fmt.Errorf("could not connect to remote repository: %w", err)
	}

	// Copy csv from the remote repository to the file store
	_, err = oras.Copy(ctx, repo, tag, fs, tag, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("could not copy from remote repository to file store: %w", err)
	}

	// Copy the signature from the remote repository to the file store
	tag = tag + ".sig"
	_, err = oras.Copy(ctx, repo, tag, fs, tag, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("could not copy from remote repository to file store: %w", err)
	}

	return nil
}
