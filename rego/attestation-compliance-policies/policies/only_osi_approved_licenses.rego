# METADATA
# title: Only OSI approved licenses
# custom:
#   description: This policy checks if there is no violation against the license allow list.
#   priority: 1
#   predicateType: https://cyclonedx.org/bom
#   relatedResources:
#   - https://docs.example.com/policy/rule/E123
#   tags:
#   - ISO 27001
#   - A.5.32 Intellectual property rights
#   complianceFrameworks:
#   - ISO 27001
package compliance

import rego.v1

default compliant := false

#
# extracted from opensource.org/licenses
# using script (just paste it into the JavaScript browser console):

# const elements = document.querySelectorAll(".license-table--spdx")

# const licenses = []
# elements.forEach(el => {
#    const licenseSpdxIdentifier = el.innerText.trim()
#    if (Boolean(licenseSpdxIdentifier)) {
#        licenses.push(el.innerText)
#    }
# })
#
# licenses

osi_approved_licenses = {
	"BSD-1-Clause",
	"AFL-3.0",
	"APL-1.0",
	"Apache-2.0",
	"Apache-1.1",
	"APSL-2.0",
	"Artistic-1.0-Perl",
	"Artistic-1.0",
	"Artistic-2.0",
	"AAL",
	"BlueOak-1.0.0",
	"BSL-1.0",
	"BSD-2-Clause-Patent",
	"CECILL-2.1",
	"CERN-OHL-P-2.0",
	"CERN-OHL-S-2.0",
	"CERN-OHL-W-2.0",
	"MIT-CMU",
	"CDDL-1.0",
	"CPAL-1.0",
	"CPL-1.0",
	"CATOSL-1.1",
	"CAL-1.0",
	"CUA-OPL-1.0",
	"EPL-1.0",
	"EPL-2.0",
	"eCos-2.0",
	"ECL-1.0",
	"ECL-2.0",
	"EFL-1.0",
	"EFL-2.0",
	"Entessa",
	"EUDatagrid",
	"EUPL-1.2",
	"Fair",
	"Frameworx-1.0",
	"AGPL-3.0-only",
	"GPL-2.0",
	"GPL-3.0-only",
	"LGPL-2.1",
	"LGPL-3.0-only",
	"LGPL-2.0-only",
	"HPND",
	"IPL-1.0",
	"ICU",
	"Intel",
	"IPA",
	"ISC",
	"Jam",
	"LPPL-1.3c",
	"BSD-3-Clause-LBNL",
	"LiLiQ-P-1.1",
	"LiLiQ-Rplus-1.1",
	"LiLiQ-R-1.1",
	"LPL-1.02",
	"LPL-1.0",
	"MS-PL",
	"MS-RL",
	"MirOS",
	"MIT-0",
	"Motosoto",
	"MPL-1.1",
	"MPL-2.0",
	"MPL-1.0",
	"MulanPSL-2.0",
	"Multics",
	"NASA-1.3",
	"Naumen",
	"NOKIA",
	"NPOSL-3.0",
	"NTP",
	"OGTSL",
	"OLFL-1.3",
	"OSL-2.1",
	"OSL-1.0",
	"OLDAP-2.8",
	"OSET-PL-2.1",
	"PHP-3.0",
	"PHP-3.01",
	"PSF-2.0",
	"RPSL-1.0",
	"RPL-1.5",
	"RPL-1.1",
	"OFL-1.1",
	"SimPL-2.0",
	"SISSL",
	"SPL-1.0",
	"BSD-2-Clause",
	"BSD-3-Clause",
	"CNRI-Python",
	"EUPL-1.1",
	"MIT",
	"NGPL",
	"OSL-3.0",
	"PostgreSQL",
	"QPL-1.0",
	"RSCPL",
	"Sleepycat",
	"Watcom-1.0",
	"UPL-1.0",
	"NCSA",
	"Unlicense",
	"VSL-0.1",
	"W3C-20150513",
	"wxWindows",
	"Xnet",
	"Zlib",
	"Unicode-DFS-2015",
	"UCL-1.0",
	"0BSD",
	"ZPL-2.0",
	"ZPL-2.1",
}

violations contains msg if {
	count(input.components[i].licenses) == 0
	msg := sprintf("Component %q has no license declared", [input.components[i].name])
}

violations contains msg if {
	input.components[i].licenses[j].license.id != ""
	not osi_approved_licenses[input.components[i].licenses[j].license.id]
	msg := sprintf("Component %q uses non-OSI approved license %q", [input.components[i].name, input.components[i].licenses[j].license.id])
}

compliant if count(violations) == 0
