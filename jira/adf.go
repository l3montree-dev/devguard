// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package jira

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
