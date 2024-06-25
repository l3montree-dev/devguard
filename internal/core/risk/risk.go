package risk

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/vulndb"
	"github.com/l3montree-dev/flawfix/internal/database/models"
)

func RawRisk(cve models.CVE, env core.Environmental) *float64 {
	e := core.SanitizeEnv(env)
	r, _ := vulndb.RiskCalculation(cve, e)
	risk := r.WithEnvironmentAndThreatIntelligence
	one := float64(1)
	epss := float64(*cve.EPSS)
	tmp := risk * (epss + one)
	// return the risk with 2 decimal places
	tmp = float64(int(tmp*100)) / 100
	return &tmp
}
