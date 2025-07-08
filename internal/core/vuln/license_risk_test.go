package vuln_test

import (
	"os"
	"slices"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/stretchr/testify/assert"
)

func TestGetOSILicenses(t *testing.T) {
	t.Run("this test can detect if the osi licenses provided by the api changed", func(t *testing.T) {

		osiApprovedLicenseIDs := []string{"0BSD", "AAL", "AFL-3.0", "AGPL-3.0-only", "APL-1.0", "APSL-2.0", "Apache-1.1", "Apache-2.0",
			"Artistic-1.0", "Artistic-1.0-Perl", "Artistic-2.0", "BSD-1-Clause", "BSD-2-Clause", "BSD-2-Clause-Patent", "BSD-3-Clause",
			"BSD-3-Clause-LBNL", "BSL-1.0", "BlueOak-1.0.0", "CAL-1.0", "CATOSL-1.1", "CDDL-1.0", "CECILL-2.1", "CERN-OHL-P-2.0", "CERN-OHL-S-2.0 ",
			"CERN-OHL-W-2.0", "CNRI-Python", "CPAL-1.0", "CPL-1.0", "CUA-OPL-1.0", "ECL-1.0", "ECL-2.0", "EFL-1.0", "EFL-2.0", "EPL-1.0", "EPL-2.0",
			"EUDatagrid", "EUPL-1.1", "EUPL-1.2", "Entessa", "Fair", "Frameworx-1.0", "GPL-2.0", "GPL-3.0-only", "HPND", "ICU", "IPA", "IPL-1.0",
			"ISC", "Intel", "Jam", "LGPL-2.0-only", "LGPL-2.1", "LGPL-3.0-only", "LPL-1.0", "LPL-1.02", "LPPL-1.3c", "LiLiQ-P-1.1", "LiLiQ-R-1.1",
			"LiLiQ-Rplus-1.1", "MIT", "MIT-0", "MIT-CMU", "MPL-1.0", "MPL-1.1", "MPL-2.0", "MS-PL", "MS-RL", "MirOS", "Motosoto", "MulanPSL-2.0", "Multics", "NASA-1.3",
			"NCSA", "NGPL", "NOKIA", "NPOSL-3.0", "NTP", "Naumen", "OFL-1.1", "OGTSL", "OLDAP-2.8", "OLFL-1.3", "OSET-PL-2.1", "OSL-1.0", "OSL-2.1",
			"OSL-3.0", "PHP-3.0", "PHP-3.01", "PSF-2.0", "PostgreSQL", "QPL-1.0", "RPL-1.1", "RPL-1.5", "RPSL-1.0", "RSCPL", "SISSL", "SPL-1.0",
			"SimPL-2.0", "Sleepycat", "UCL-1.0", "UPL-1.0", "Unicode-DFS-2015", "Unlicense", "VSL-0.1", "W3C-20150513", "Watcom-1.0", "Xnet",
			"ZPL-2.0", "ZPL-2.1", "Zlib", "eCos-2.0", "wxWindows"}

		os.Setenv("OSI_LICENSES_API", "https://opensource.org/api/license/")
		result, err := vuln.GetOSILicenses()
		assert.Nil(t, err)
		assert.Equal(t, len(osiApprovedLicenseIDs), len(result))
		slices.Sort(osiApprovedLicenseIDs)
		slices.Sort(result)
		assert.Equal(t, osiApprovedLicenseIDs, result)
	})
}
