package risk

import (
	"fmt"
	"strings"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/obj"
	"github.com/l3montree-dev/devguard/internal/utils"
)

func RiskToSeverity(risk float64) string {
	switch {
	case risk < 4:
		return "Low"
	case risk < 7:
		return "Medium"
	case risk < 9:
		return "High"
	case risk <= 10:
	default:
		return "None"
	}
	return "None"
}

// returns hex without leading "#"
func RiskToColor(risk float64) string {
	switch {
	case risk < 4:
		return "00FF00"
	case risk < 7:
		return "FFFF00"
	case risk < 9:
		return "FFA500"
	case risk <= 10:
	default:
		return "FF0000"
	}
	return "FF0000"
}

// parseCvssVector parses the CVSS vector and returns a map of its components.
func parseCvssVector(vector string) map[string]string {
	parts := strings.Split(vector, "/")
	res := make(map[string]string)
	for _, part := range parts[1:] {
		p := strings.Split(part, ":")
		res[p[0]] = p[1]
	}
	return res
}

// exploitMessage generates a short and long message based on the exploitability.
func exploitMessage(vuln models.DependencyVulnerability, obj map[string]string) (short string, long string) {
	if obj["E"] == "POC" || obj["E"] == "P" {
		short = "Proof of Concept"
		long = "A proof of concept is available for this vulnerability:\n"
		for _, exploit := range vuln.CVE.Exploits {
			long += exploit.SourceURL + "\n"
		}
	} else if obj["E"] == "F" {
		short = "Functional"
		long = "A functional exploit is available for this vulnerability:\n"
		for _, exploit := range vuln.CVE.Exploits {
			long += exploit.SourceURL + "\n"
		}
	} else if obj["E"] == "A" {
		short = "Attacked"
		long = "This vulnerability is actively being exploited in the wild. Please take immediate action to mitigate the risk."
	} else {
		short = "Not available"
		long = "We did not find any exploit available. Neither in GitHub repositories nor in the Exploit-Database. There are no script kiddies exploiting this vulnerability."
	}
	return
}

// epssMessage generates a message based on the EPSS score.
func epssMessage(epss float64) string {
	switch {
	case epss < 0.1:
		return "The exploit probability is very low. The vulnerability is unlikely to be exploited in the next 30 days."
	case epss < 0.2:
		return "The exploit probability is low. The vulnerability is unlikely to be exploited in the next 30 days."
	case epss < 0.4:
		return "The exploit probability is moderate. The vulnerability is likely to be exploited in the next 30 days."
	case epss < 0.6:
		return "The exploit probability is high. The vulnerability is very likely to be exploited in the next 30 days."
	case epss < 0.8:
		return "The exploit probability is very high. The vulnerability is very likely to be exploited in the next 30 days."
	default:
		return "The exploit probability is critical. The vulnerability is very likely to be exploited in the next 30 days."
	}
}

// componentDepthMessages generates a message based on the component depth.
func componentDepthMessages(depth int) string {
	if depth == 1 {
		return "The vulnerability is in a direct dependency of your project."
	}
	return fmt.Sprintf("The vulnerability is in a dependency of a dependency your project. It is %d levels deep.", depth)
}

type AssetDTO struct {
	AvailabilityRequirement    string
	IntegrityRequirement       string
	ConfidentialityRequirement string
}

const (
	RequirementsLevelHigh = "High"
)

// cvssBE generates a message based on the asset and CVSS object.
func cvssBE(asset models.Asset, cvssObj map[string]string) string {
	elements := []string{}

	if asset.AvailabilityRequirement == RequirementsLevelHigh && cvssObj["A"] == "H" {
		elements = append(elements, "- Exploiting this vulnerability is critical because the asset requires high availability, and the vulnerability significantly impacts availability.")
	} else if cvssObj["A"] == "H" {
		elements = append(elements, "- Exploiting this vulnerability significantly impacts availability.")
	}

	if asset.IntegrityRequirement == RequirementsLevelHigh && cvssObj["I"] == "H" {
		elements = append(elements, "- Exploiting this vulnerability is critical because the asset requires high integrity, and the vulnerability significantly impacts integrity.")
	} else if cvssObj["I"] == "H" {
		elements = append(elements, "- Exploiting this vulnerability significantly impacts integrity.")
	}

	if asset.ConfidentialityRequirement == RequirementsLevelHigh && cvssObj["C"] == "H" {
		elements = append(elements, "- Exploiting this vulnerability is critical because the asset requires high confidentiality, and the vulnerability significantly impacts confidentiality.")
	} else if cvssObj["C"] == "H" {
		elements = append(elements, "- Exploiting this vulnerability significantly impacts confidentiality.")
	}
	return strings.Join(elements, "\n")
}

var baseScores = map[string]map[string]string{
	"AV": {
		"N": "The vulnerability can be exploited over the network without needing physical access.",
		"A": "The vulnerability can be exploited over a local network, such as Wi-Fi.",
		"L": "The vulnerability requires local access to the device to be exploited.",
		"P": "The vulnerability requires physical access to the device to be exploited.",
	},
	"AC": {
		"L": "It is easy for an attacker to exploit this vulnerability.",
		"H": "It is difficult for an attacker to exploit this vulnerability and may require special conditions.",
	},
	"PR": {
		"N": "An attacker does not need any special privileges or access rights.",
		"L": "An attacker needs basic access or low-level privileges.",
		"H": "An attacker needs high-level or administrative privileges.",
	},
	"UI": {
		"N": "No user interaction is needed for the attacker to exploit this vulnerability.",
		"R": "The attacker needs the user to perform some action, like clicking a link.",
	},
	"S": {
		"U": "The impact is confined to the system where the vulnerability exists.",
		"C": "The vulnerability can affect other systems as well, not just the initial system.",
	},
	"C": {
		"H": "There is a high impact on the confidentiality of the information.",
		"L": "There is a low impact on the confidentiality of the information.",
		"N": "",
	},
	"I": {
		"H": "There is a high impact on the integrity of the data.",
		"L": "There is a low impact on the integrity of the data.",
		"N": "",
	},
	"A": {
		"H": "There is a high impact on the availability of the system.",
		"L": "There is a low impact on the availability of the system.",
		"N": "",
	},
}

var order = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

// describeCVSS generates a description of the CVSS vector.
func describeCVSS(cvss map[string]string) string {
	var descriptions []string
	for _, key := range order {
		if desc, ok := baseScores[key][cvss[key]]; ok {
			descriptions = append(descriptions, desc)
		}
	}

	// create a bullet point list to improve readability
	descriptions[0] = "- " + descriptions[0]
	// remove empty strings
	descriptions = utils.Filter(descriptions, func(s string) bool {
		return s != ""
	})

	return strings.Join(descriptions, "\n- ")
}

type Explanation struct {
	obj.RiskMetrics

	exploitMessage struct {
		Short string
		Long  string
	}
	epssMessage           string
	cvssBEMessage         string
	componentDepthMessage string
	cvssMessage           string
	vulnId                string
	risk                  float64

	depth int
	epss  float64

	cveId          string
	cveDescription string

	affectedComponentName string
	scanner               string
	fixedVersion          *string
}

func (e Explanation) Markdown(baseUrl, orgSlug, projectSlug, assetSlug string) string {
	var str strings.Builder
	str.WriteString(fmt.Sprintf("# %s\n", e.cveId))
	str.WriteString(e.cveDescription)
	str.WriteString("\n")
	str.WriteString("### Affected component \n")
	str.WriteString(fmt.Sprintf("The vulnerability is in `%s`, detected by the `%s` scan.\n", e.affectedComponentName, e.scanner))
	str.WriteString("### Recommended fix\n")
	if e.fixedVersion != nil {
		str.WriteString(fmt.Sprintf("Upgrade to version %s or later.\n", *e.fixedVersion))
	} else {
		str.WriteString("No fix is available.\n")
	}
	str.WriteString("\n")
	str.WriteString(fmt.Sprintf("## Risk: `%.2f (%s)`\n", e.risk, RiskToSeverity(e.risk)))
	str.WriteString(fmt.Sprintf("### EPSS: `%.2f %%`\n", e.epss*100))
	str.WriteString(fmt.Sprintf("%s\n", e.epssMessage))
	str.WriteString("\n")
	str.WriteString(fmt.Sprintf("### Exploit: `%s`\n", e.exploitMessage.Short))
	str.WriteString(e.exploitMessage.Long)
	str.WriteString("\n")
	str.WriteString(fmt.Sprintf("### Vulnerability Depth: `%d`\n", e.depth))
	str.WriteString(fmt.Sprintf("%s\n", e.componentDepthMessage))
	str.WriteString("\n")
	str.WriteString(fmt.Sprintf("### CVSS-BE: `%.1f`\n", e.WithEnvironment))
	str.WriteString(fmt.Sprintf("%s\n", e.cvssBEMessage))
	str.WriteString("\n")
	str.WriteString(fmt.Sprintf("### CVSS-B: `%.1f`\n", e.BaseScore))
	str.WriteString(fmt.Sprintf("%s\n", e.cvssMessage))
	str.WriteString("\n")
	str.WriteString(fmt.Sprintf("More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/vulns/%s)", baseUrl, orgSlug, projectSlug, assetSlug, e.vulnId))
	str.WriteString("\n")
	// add information about slash commands
	// ref: https://github.com/l3montree-dev/devguard/issues/180
	str.WriteString("\n")
	str.WriteString("### Slash Commands\n")
	str.WriteString("You can use the following slash commands to interact with this vulnerability:\n")
	str.WriteString("- `/accept <Justification>` or `/a <Justification>` - Accept the risk\n")
	str.WriteString("- `/false-positive <Justification>` or `/fp <Justification>` - Mark the risk as false positive\n")
	str.WriteString("- `/reopen <Justification>` or `/r <Justification>` - Reopen the risk\n")

	return str.String()
}

// provide the vector and risk metrics obtained from the risk calculation
func Explain(vuln models.DependencyVulnerability, asset models.Asset, vector string, riskMetrics obj.RiskMetrics) Explanation {
	cvss := parseCvssVector(vector)

	shortMsg, longMsg := exploitMessage(vuln, cvss)

	return Explanation{
		exploitMessage: struct {
			Short string
			Long  string
		}{
			Short: shortMsg,
			Long:  longMsg,
		},
		epssMessage:           epssMessage(utils.OrDefault(vuln.CVE.EPSS, 0)),
		cvssBEMessage:         cvssBE(asset, cvss),
		componentDepthMessage: componentDepthMessages(*vuln.ComponentDepth),
		cvssMessage:           describeCVSS(cvss),
		vulnId:                vuln.ID,

		risk:  utils.OrDefault(vuln.RawRiskAssessment, 0),
		epss:  utils.OrDefault(vuln.CVE.EPSS, 0),
		depth: utils.OrDefault(vuln.ComponentDepth, 0),

		RiskMetrics:    riskMetrics,
		cveId:          *vuln.CVEID,
		cveDescription: vuln.CVE.Description,

		affectedComponentName: utils.SafeDereference(vuln.ComponentPurl),
		scanner:               vuln.ScannerID,
		fixedVersion:          vuln.ComponentFixedVersion,
	}
}
