package risk

import (
	"fmt"
	"strings"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

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
func exploitMessage(flaw models.Flaw, obj map[string]string) (short string, long string) {
	if obj["E"] == "POC" || obj["E"] == "P" {
		short = "Proof of Concept"
		long = "A proof of concept is available for this vulnerability:\n"
		for _, exploit := range flaw.CVE.Exploits {
			long += exploit.SourceURL + "\n"
		}
	} else if obj["E"] == "F" {
		short = "Functional"
		long = "A functional exploit is available for this vulnerability:\n"
		for _, exploit := range flaw.CVE.Exploits {
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
	var str strings.Builder

	if asset.AvailabilityRequirement == RequirementsLevelHigh && cvssObj["A"] == "H" {
		str.WriteString("Exploiting this vulnerability is critical because the asset requires high availability, and the vulnerability significantly impacts availability.")
	} else if cvssObj["A"] == "H" {
		str.WriteString("Exploiting this vulnerability significantly impacts availability.")
	}

	if asset.IntegrityRequirement == RequirementsLevelHigh && cvssObj["I"] == "H" {
		str.WriteString("Exploiting this vulnerability is critical because the asset requires high integrity, and the vulnerability significantly impacts integrity.")
	} else if cvssObj["I"] == "H" {
		str.WriteString("Exploiting this vulnerability significantly impacts integrity.")
	}

	if asset.ConfidentialityRequirement == RequirementsLevelHigh && cvssObj["C"] == "H" {
		str.WriteString("Exploiting this vulnerability is critical because the asset requires high confidentiality, and the vulnerability significantly impacts confidentiality.")
	} else if cvssObj["C"] == "H" {
		str.WriteString("Exploiting this vulnerability significantly impacts confidentiality.")
	}
	return str.String()
}

// describeCVSS generates a description of the CVSS vector.
func describeCVSS(cvss map[string]string) string {
	baseScores := map[string]map[string]string{
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

	order := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	var descriptions []string
	for _, key := range order {
		if desc, ok := baseScores[key][cvss[key]]; ok {
			descriptions = append(descriptions, desc)
		}
	}
	return strings.Join(descriptions, "\n")
}

type Explanation struct {
	ExploitMessage struct {
		Short string
		Long  string
	}
	EpssMessage           string
	CvssBEMessage         string
	ComponentDepthMessage string
	CvssMessage           string
	flawId                string
	risk                  float64

	cvss  float64
	cveId string
}

func (e Explanation) Markdown(baseUrl, orgSlug, projectSlug, assetSlug string) string {
	var str strings.Builder
	str.WriteString(fmt.Sprintf("# %s\n", e.cveId))
	str.WriteString(fmt.Sprintf("## Risk: %f\n", e.risk))
	str.WriteString("## Risk Explanation\n")
	str.WriteString("### EPSS\n")
	str.WriteString(fmt.Sprintf("%s\n", e.EpssMessage))
	str.WriteString("\n")
	str.WriteString("### Exploit\n")
	str.WriteString(fmt.Sprintf("**Short:** %s\n", e.ExploitMessage.Short))
	str.WriteString(fmt.Sprintf("**Long:** %s\n", e.ExploitMessage.Long))
	str.WriteString("\n")
	str.WriteString("### Vulnerability Depth\n")
	str.WriteString(fmt.Sprintf("%s\n", e.ComponentDepthMessage))
	str.WriteString("\n")
	str.WriteString("### CVSS-BE\n")
	str.WriteString(fmt.Sprintf("%s\n", e.CvssBEMessage))
	str.WriteString("\n")
	str.WriteString(fmt.Sprintf("### CVSS (%f)\n", e.cvss))
	str.WriteString(fmt.Sprintf("%s\n", e.CvssMessage))
	str.WriteString("\n")
	str.WriteString(fmt.Sprintf("More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/flaws/%s)", baseUrl, orgSlug, projectSlug, assetSlug, e.flawId))
	return str.String()
}

func Explain(flaw models.Flaw, asset models.Asset) Explanation {
	// Example usage
	cvssVector := flaw.CVE.Vector
	cvss := parseCvssVector(cvssVector)

	shortMsg, longMsg := exploitMessage(flaw, cvss)

	depth := int(flaw.GetArbitraryJsonData()["componentDepth"].(float64))

	return Explanation{
		ExploitMessage: struct {
			Short string
			Long  string
		}{
			Short: shortMsg,
			Long:  longMsg,
		},
		EpssMessage:           epssMessage(utils.OrDefault(flaw.CVE.EPSS, 0)),
		CvssBEMessage:         cvssBE(asset, cvss),
		ComponentDepthMessage: componentDepthMessages(depth),
		CvssMessage:           describeCVSS(cvss),
		flawId:                flaw.ID,

		risk: utils.OrDefault(flaw.RawRiskAssessment, 0),
	}
}
