package assetversion

// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// VulnerabilityInReport represents a single CVE entry in the template.
type VulnerabilityInReport struct {
	CVEID               string
	SourceName          string
	SourceURL           string
	AffectedComponent   string
	CveDescription      string
	AnalysisState       string
	AnalysisResponse    string
	AnalysisDetail      string
	AnalysisFirstIssued string
	AnalysisLastUpdated string
	CVSS                float64
	Severity            string
	CVSSMethod          string
	Vector              string
	DevguardScore       float64
	DevguardSeverity    string
	DevguardVector      string
}

// VulnerabilityReport is the top-level model matching the markdown.gotmpl context.
type VulnerabilityReport struct {
	AppTitle           string
	AppVersion         string
	ReportCreationDate string
	AmountCritical     int
	AmountHigh         int
	AmountMedium       int
	AmountLow          int
	AvgFixTimeCritical string
	AvgFixTimeHigh     string
	AvgFixTimeMedium   string
	AvgFixTimeLow      string
	CriticalVulns      []VulnerabilityInReport
	HighVulns          []VulnerabilityInReport
	MediumVulns        []VulnerabilityInReport
	LowVulns           []VulnerabilityInReport
}
