package cwe

import (
	"fmt"
	"strings"
)

func (w WeaknessType) toModel() CWEModel {

	return CWEModel{
		CWE:         fmt.Sprintf("CWE-%d", w.IDAttr),
		Description: strings.ReplaceAll(strings.TrimSpace(w.Description), "\n", " "),
	}
}
