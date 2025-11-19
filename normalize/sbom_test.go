package normalize

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMapCDXToStatus(t *testing.T) {
	cases := []struct {
		name     string
		analysis *cdx.VulnerabilityAnalysis
		want     string
	}{
		{name: "nil analysis", analysis: nil, want: ""},
		{name: "resolved", analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved}, want: "fixed"},
		{name: "false positive", analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASFalsePositive}, want: "falsePositive"},
		{name: "exploitable", analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable}, want: "open"},
		{name: "in triage", analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASInTriage}, want: "open"},
		{name: "response update fallback", analysis: &cdx.VulnerabilityAnalysis{State: "", Response: &[]cdx.ImpactAnalysisResponse{cdx.IARUpdate}}, want: "fixed"},
		{name: "response will not fix fallback", analysis: &cdx.VulnerabilityAnalysis{State: "", Response: &[]cdx.ImpactAnalysisResponse{cdx.IARWillNotFix}}, want: "accepted"},
		{name: "unknown response", analysis: &cdx.VulnerabilityAnalysis{State: "", Response: &[]cdx.ImpactAnalysisResponse{"unknown"}}, want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MapCDXToVulnStatus(tc.analysis)
			assert.Equal(t, tc.want, got)
		})
	}
}
