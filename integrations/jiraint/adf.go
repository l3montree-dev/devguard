// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package jiraint

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/vulndb"
)

func descriptionADF(adf *ADF) {
	adf.Content = append(adf.Content,
		ADFContent{
			Type: "heading",
			Attrs: &ADFMarkAttributes{
				Level: 3,
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "Interact with this vulnerability",
				},
			},
		},
		ADFContent{
			Type: "paragraph",
			Content: []ADFContent{
				{
					Type: "text",
					Text: "You can use the following slash commands to interact with this vulnerability:",
				},
			},
		},
	)
}
func acceptedRiskADF(adf *ADF) {
	adf.Content = append(adf.Content,
		ADFContent{
			Type: "heading",
			Attrs: &ADFMarkAttributes{
				Level: 4,
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "Reply with this to acknowledge and accept the identified risk.",
				},
			},
		},
		ADFContent{
			Type: "codeBlock",
			Attrs: &ADFMarkAttributes{
				Language: "text",
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "/accept I accept the risk of this vulnerability, because ...",
				},
			},
		},
	)
}

func falsePositiveDependencyVulnADF(adf *ADF) {
	adf.Content = append(adf.Content,
		ADFContent{
			Type: "heading",
			Attrs: &ADFMarkAttributes{
				Level: 4,
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "Mark the risk as false positive: Use one of these commands if you believe the reported vulnerability is not actually a valid issue.",
				},
			},
		},
		ADFContent{
			Type: "codeBlock",
			Attrs: &ADFMarkAttributes{
				Language: "text",
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "/component-not-present The vulnerable component is not included in the artifact.",
				},
			},
		},
		ADFContent{
			Type: "codeBlock",
			Attrs: &ADFMarkAttributes{
				Language: "text",
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "/vulnerable-code-not-present The component is present, but the vulnerable code is not included or compiled.",
				},
			},
		},
		ADFContent{
			Type: "codeBlock",
			Attrs: &ADFMarkAttributes{
				Language: "text",
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "/vulnerable-code-not-in-execute-path The vulnerable code exists, but is never executed at runtime.",
				},
			},
		},
		ADFContent{
			Type: "codeBlock",
			Attrs: &ADFMarkAttributes{
				Language: "text",
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "/vulnerable-code-cannot-be-controlled-by-adversary Built-in protections prevent exploitation of this vulnerability.",
				},
			},
		},
		ADFContent{
			Type: "codeBlock",
			Attrs: &ADFMarkAttributes{
				Language: "text",
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "/inline-mitigations-already-exist The vulnerable code cannot be controlled or influenced by an attacker.",
				},
			},
		},
	)
}

func falsePositiveFirstPartyVulnADF(adf *ADF) {
	adf.Content = append(adf.Content,
		ADFContent{
			Type: "heading",
			Attrs: &ADFMarkAttributes{
				Level: 4,
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "Mark the risk as false positive: Use this command if you believe the reported vulnerability is not actually a valid issue.",
				},
			},
		},
		ADFContent{
			Type: "codeBlock",
			Attrs: &ADFMarkAttributes{
				Language: "text",
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "/false-positive The vulnerability is not exploitable in this context.",
				},
			},
		},
	)
}

func reopenRiskADF(adf *ADF) {
	adf.Content = append(adf.Content,
		ADFContent{
			Type: "heading",
			Attrs: &ADFMarkAttributes{
				Level: 4,
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "Reopen the risk: Use this command to reopen a previously closed or accepted vulnerability.",
				},
			},
		},
		ADFContent{
			Type: "codeBlock",
			Attrs: &ADFMarkAttributes{
				Language: "text",
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: "/reopen ...",
				},
			},
		},
	)
}

func AddSlashCommandsToDependencyVulnADF(adf *ADF) {
	descriptionADF(adf)
	acceptedRiskADF(adf)
	falsePositiveDependencyVulnADF(adf)
	reopenRiskADF(adf)
}

func AddSlashCommandsToToFirstPartyVulnADF(adf *ADF) {
	descriptionADF(adf)
	acceptedRiskADF(adf)
	falsePositiveFirstPartyVulnADF(adf)
	reopenRiskADF(adf)
}

func RenderADF(firstPartyVuln models.FirstPartyVuln, baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug string) ADF {
	snippets, err := transformer.FromJSONSnippetContents(firstPartyVuln)
	if err != nil {
		slog.Error("could not parse snippet contents", "error", err)
		return ADF{}
	}

	adf := ADF{
		Version: 1,
		Type:    "doc",
		Content: []ADFContent{
			{
				Type: "paragraph",
				Content: []ADFContent{
					{
						Type: "text",
						Text: *firstPartyVuln.Message,
					},
				},
			},
		},
	}

	for _, snippet := range snippets.Snippets {
		adf.Content = append(adf.Content, ADFContent{
			Type: "codeBlock",
			Content: []ADFContent{
				{
					Type: "text",
					Text: snippet.Snippet,
				},
			},
		})
	}

	if firstPartyVuln.URI != "" {
		link := strings.TrimPrefix(firstPartyVuln.URI, "/")
		adf.Content = append(adf.Content, ADFContent{
			Type: "paragraph",
			Content: []ADFContent{
				{
					Type: "text",
					Text: "File: " + link,
				},
			},
		})
	}

	adf.Content = append(adf.Content, ADFContent{
		Type: "paragraph",
		Content: []ADFContent{
			{
				Type: "text",
				Text: fmt.Sprintf("More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/dependency-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, firstPartyVuln.ID),
			},
		},
	})

	//add slash commands
	AddSlashCommandsToToFirstPartyVulnADF(&adf)

	return adf
}

func GenerateADF(e vulndb.Explanation, baseURL, orgSlug, projectSlug, assetSlug, assetVersionName string, mermaidPathToComponent string) ADF {

	artifactNames := strings.Fields(e.ArtifactNames)
	for i, s := range artifactNames {
		artifactNames[i] = fmt.Sprintf("`%s`", s)
	}

	//add the description of the vulnerability
	adf := ADF{
		Version: 1,
		Type:    "doc",
		Content: []ADFContent{
			{
				Type: "paragraph",
				Content: []ADFContent{
					{
						Type: "text",
						Text: e.CVEDescription,
					},
				},
			},
		},
	}

	//add the affected component
	adf.Content = append(adf.Content, ADFContent{
		Type: "heading",
		Attrs: &ADFMarkAttributes{
			Level: 3,
		},
		Content: []ADFContent{
			{
				Type: "text",
				Text: "Affected component",
			},
		},
	})
	adf.Content = append(adf.Content, ADFContent{
		Type: "paragraph",
		Content: []ADFContent{
			{
				Type: "text",
				Text: fmt.Sprintf("The vulnerability is in `%s`, found in artifacts %s.\n", e.ComponentPurl, strings.Join(artifactNames, ", ")),
			},
		},
	})

	//add fixed version and commands to fix the package
	adf.Content = append(adf.Content, ADFContent{
		Type: "heading",
		Attrs: &ADFMarkAttributes{
			Level: 3,
		},
		Content: []ADFContent{
			{
				Type: "text",
				Text: "Recommended fix",
			},
		},
	})
	if e.FixedVersion != nil {
		adf.Content = append(adf.Content, ADFContent{
			Type: "paragraph",
			Content: []ADFContent{
				{
					Type: "text",
					Text: fmt.Sprintf("Upgrade to version %s or later.\n", *e.FixedVersion),
				},
			},
		})

		adf.Content = append(adf.Content, ADFContent{
			Type: "codeBlock",
			Attrs: &ADFMarkAttributes{
				Language: "text",
			},
			Content: []ADFContent{
				{
					Type: "text",
					Text: e.GenerateCommandsToFixPackage(),
				},
			},
		})

	} else {
		adf.Content = append(adf.Content, ADFContent{
			Type: "paragraph",
			Content: []ADFContent{
				{
					Type: "text",
					Text: "No fix is available.\n",
				},
			},
		})

	}
	//add additional guidance for mitigating vulnerabilities
	adf.Content = append(adf.Content, ADFContent{
		Type: "heading",
		Attrs: &ADFMarkAttributes{
			Level: 3,
		},
		Content: []ADFContent{
			{
				Type: "text",
				Text: "Additional guidance for mitigating vulnerabilities",
			},
		},
	})
	adf.Content = append(adf.Content, ADFContent{
		Type: "paragraph",
		Content: []ADFContent{
			{
				Type: "text",
				Text: "Visit our guides on ",
			},
			{
				Type: "text",
				Text: "devguard.org",
				Marks: []ADFMark{
					{
						Type: "link",
						Attrs: &ADFMarkAttributes{
							Href: "https://devguard.org/risk-mitigation-guides/software-composition-analysis",
						},
					},
					{
						Type: "underline",
					},
				},
			},
		},
	})

	//add table with risk factors
	adf.Content = append(adf.Content, ADFContent{
		Type:  "table",
		Attrs: &ADFMarkAttributes{},
		Content: []ADFContent{
			{
				Type: "tableRow",
				Content: []ADFContent{
					{
						Type:  "tableHeader",
						Attrs: &ADFMarkAttributes{},
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: "Risk Factor",
										Marks: []ADFMark{
											{
												Type: "strong",
											},
										},
									},
								},
							},
						},
					},
					{
						Type:  "tableHeader",
						Attrs: &ADFMarkAttributes{},
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: "Value",
										Marks: []ADFMark{
											{
												Type: "strong",
											},
										},
									},
								},
							},
						},
					},
					{
						Type:  "tableHeader",
						Attrs: &ADFMarkAttributes{},
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: "Description",
										Marks: []ADFMark{
											{
												Type: "strong",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			{
				Type: "tableRow",
				Content: []ADFContent{
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: "Vulnerability Depth",
									},
								},
							},
						},
					},
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: fmt.Sprintf("`%d`", e.Depth),
									},
								},
							},
						},
					},
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: e.ComponentDepthMessage,
									},
								},
							},
						},
					},
				},
			},
			{
				Type: "tableRow",
				Content: []ADFContent{
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: "EPSS",
									},
								},
							},
						},
					},
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: fmt.Sprintf("`%.2f %%`", e.EPSS*100),
									},
								},
							},
						},
					},
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: e.EPSSMessage,
									},
								},
							},
						},
					},
				},
			},
			{
				Type: "tableRow",
				Content: []ADFContent{
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: "EXPLOIT",
									},
								},
							},
						},
					},
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: fmt.Sprintf("`%s`", e.ExploitMessage.Short),
									},
								},
							},
						},
					},
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: e.ExploitMessage.Long,
									},
								},
							},
						},
					},
				},
			},
			{
				Type: "tableRow",
				Content: []ADFContent{
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: "CVSS-BE",
									},
								},
							},
						},
					},
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: fmt.Sprintf("`%.1f`", e.WithEnvironment),
									},
								},
							},
						},
					},
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: e.CVSSBEMessage,
									},
								},
							},
						},
					},
				},
			},
			{
				Type: "tableRow",
				Content: []ADFContent{
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: "CVSS-B",
									},
								},
							},
						},
					},
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: fmt.Sprintf("`%.1f`", e.BaseScore),
									},
								},
							},
						},
					},
					{
						Type: "tableCell",
						Content: []ADFContent{
							{
								Type: "paragraph",
								Content: []ADFContent{
									{
										Type: "text",
										Text: e.CVSSMessage,
									},
								},
							},
						},
					},
				},
			},
		},
	})

	// add information about the path to the component
	adf.Content = append(adf.Content, ADFContent{
		Type: "paragraph",
		Content: []ADFContent{
			{
				Type: "text",
				Text: "More details can be found in ",
			},
			{
				Type: "text",
				Text: "DevGuard",
				Marks: []ADFMark{
					{
						Type: "link",
						Attrs: &ADFMarkAttributes{
							Href: fmt.Sprintf("%s/%s/projects/%s/assets/%s/refs/%s/dependency-risks/%s", baseURL, orgSlug, projectSlug, assetSlug, assetVersionName, e.DependencyVulnID),
						},
					},
					{
						Type: "underline",
					},
				},
			},
		},
	})

	// add the commands to interact with the vulnerability
	AddSlashCommandsToDependencyVulnADF(&adf)
	return adf
}
