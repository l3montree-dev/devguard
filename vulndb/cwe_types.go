package vulndb

import (
	"fmt"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
)

func (w WeaknessType) toModel() models.CWE {
	return models.CWE{
		CWE:         fmt.Sprintf("CWE-%d", w.IDAttr),
		Description: strings.ReplaceAll(strings.TrimSpace(w.Description), "\n", " "),
	}
}
