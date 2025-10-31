package normalize

import (
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type SBOM interface {
	GetComponents() *[]cdx.Component
	GetDependencies() *[]cdx.Dependency
	GetMetadata() *cdx.Metadata
	GetCdxBom() *cdx.BOM
	GetOrigin() string
	GetVulnerabilities() *[]cdx.Vulnerability
	Eject() *cdx.BOM
}

// map CycloneDX Analysis State / Response to internal status strings used by CreateVulnEventAndApply
func MapCDXToVulnStatus(a *cdx.VulnerabilityAnalysis) string {
	if a == nil {
		return ""
	}
	switch a.State {
	case cdx.IASResolved:
		return "fixed"
	case cdx.IASFalsePositive:
		return "falsePositive"
	case cdx.IASExploitable:
		// check if wont fix
		if a.Response != nil {
			if slices.Contains(*a.Response, cdx.IARWillNotFix) {
				return "accepted"
			}
		}
		return "open"
	case cdx.IASInTriage:
		return "open"
	default:
		// fallback to response mapping if state is empty
		if a.Response != nil && len(*a.Response) > 0 {
			// take first response
			switch (*a.Response)[0] {
			case cdx.IARUpdate:
				return "fixed"
			case cdx.IARWillNotFix:
				return "accepted"
			default:
				return ""
			}
		}
		return ""
	}
}

func MapCDXToEventType(a *cdx.VulnerabilityAnalysis) string {
	if a == nil {
		return ""
	}
	switch a.State {
	case cdx.IASResolved:
		return "fixed"
	case cdx.IASFalsePositive:
		return "falsePositive"
	case cdx.IASExploitable:
		// check if wont fix
		if a.Response != nil {
			if slices.Contains(*a.Response, cdx.IARWillNotFix) {
				return "accepted"
			}
		}
		return "detected"
	case cdx.IASInTriage:
		return "detected"
	default:
		// fallback to response mapping if state is empty
		if a.Response != nil && len(*a.Response) > 0 {
			// take first response
			switch (*a.Response)[0] {
			case cdx.IARUpdate:
				return "fixed"
			case cdx.IARWillNotFix:
				return "accepted"
			default:
				return ""
			}
		}
		return ""
	}
}
