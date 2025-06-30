// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package common

import "github.com/l3montree-dev/devguard/internal/core/integrations/jira"

func AddSlashCommandsToADF(adf *jira.ADF) {

	adf.Content = append(adf.Content,
		jira.ADFContent{
			Type: "heading",
			Attrs: &jira.ADFMarkAttributes{
				Level: 3,
			},
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "Interact with this vulnerability",
				},
			},
		},
		jira.ADFContent{
			Type: "paragraph",
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "You can use the following slash commands to interact with this vulnerability:",
				},
			},
		},
		jira.ADFContent{
			Type: "heading",
			Attrs: &jira.ADFMarkAttributes{
				Level: 4,
			},
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "👍   Reply with this to acknowledge and accept the identified risk.",
				},
			},
		},
		jira.ADFContent{
			Type: "codeBlock",
			Attrs: &jira.ADFMarkAttributes{
				Language: "text",
			},
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "/accept I accept the risk of this vulnerability, because ...",
				},
			},
		},
		jira.ADFContent{
			Type: "heading",
			Attrs: &jira.ADFMarkAttributes{
				Level: 4,
			},
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "⚠️ Mark the risk as false positive: Use one of these commands if you believe the reported vulnerability is not actually a valid issue.",
				},
			},
		},
		jira.ADFContent{
			Type: "codeBlock",
			Attrs: &jira.ADFMarkAttributes{
				Language: "text",
			},
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "/component-not-present The vulnerable component is not included in the artifact.",
				},
			},
		},
		jira.ADFContent{
			Type: "codeBlock",
			Attrs: &jira.ADFMarkAttributes{
				Language: "text",
			},
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "/vulnerable-code-not-present The component is present, but the vulnerable code is not included or compiled.",
				},
			},
		},
		jira.ADFContent{
			Type: "codeBlock",
			Attrs: &jira.ADFMarkAttributes{
				Language: "text",
			},
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "/vulnerable-code-not-in-execute-path The vulnerable code exists, but is never executed at runtime.",
				},
			},
		},
		jira.ADFContent{
			Type: "codeBlock",
			Attrs: &jira.ADFMarkAttributes{
				Language: "text",
			},
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "/vulnerable-code-cannot-be-controlled-by-adversary Built-in protections prevent exploitation of this vulnerability.",
				},
			},
		},
		jira.ADFContent{
			Type: "codeBlock",
			Attrs: &jira.ADFMarkAttributes{
				Language: "text",
			},
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "/inline-mitigations-already-exist The vulnerable code cannot be controlled or influenced by an attacker.",
				},
			},
		},
		jira.ADFContent{
			Type: "heading",
			Attrs: &jira.ADFMarkAttributes{
				Level: 4,
			},
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "🔁  Reopen the risk: Use this command to reopen a previously closed or accepted vulnerability.",
				},
			},
		},
		jira.ADFContent{
			Type: "codeBlock",
			Attrs: &jira.ADFMarkAttributes{
				Language: "text",
			},
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "/reopen ...",
				},
			},
		},
	)
}
