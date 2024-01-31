package vulndb

import (
	"fmt"
	"strings"
)

func (w WeaknessType) toModel() CWE {
	return CWE{
		CWE:         fmt.Sprintf("CWE-%d", w.IDAttr),
		Description: strings.ReplaceAll(strings.TrimSpace(w.Description), "\n", " "),
	}
}
