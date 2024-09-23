package vulndb

import (
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestGroupAffectedComponentsByCVE(t *testing.T) {
	t.Run("should correctly group affected components by CVE", func(t *testing.T) {
		testdata := [][]string{
			{"a", "CVE-2023-1234"},
			{"b", "CVE-2023-1234"},
			{"c", "CVE-2023-1234"},
			{"a", "CVE-2023-5678"},
		}
		group := groupAffectedComponentsByCVE(testdata)
		expected := map[string][]string{
			"CVE-2023-1234": {"a", "b", "c"},
			"CVE-2023-5678": {"a"},
		}

		assert.Equal(t, expected, group)
	})
}

func TestImportCVEAffectedComponent(t *testing.T) {
	t.Run("should correctly import the testdata/cve_affected_component.csv", func(t *testing.T) {
		// create a cve repository mock
		cveRepository := mocks.VulndbCvesRepository{}

		// see the csv file to validate.
		// expect a grouping by cve id
		cveRepository.On("SaveCveAffectedComponents", (*gorm.DB)(nil), "CVE-2023-1234", []string{"a", "b", "c"}).Return(nil)
		cveRepository.On("SaveCveAffectedComponents", (*gorm.DB)(nil), "CVE-2023-5678", []string{"a"}).Return(nil)

		s := importService{
			cveRepository: &cveRepository,
		}

		f, err := os.OpenFile("testdata/cve_affected_component.csv", os.O_RDONLY, 0644)

		assert.NoError(t, err)

		err = s.importCveAffectedComponent(nil, f)
		assert.NoError(t, err)
		cveRepository.AssertExpectations(t)
	})
}
