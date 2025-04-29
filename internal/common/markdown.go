package common

import "strings"

func AddSlashCommands(str *strings.Builder) *strings.Builder {
	str.WriteString("\n--- \n")

	str.WriteString("### Interact with this vulnerability\n")
	str.WriteString("You can use the following slash commands to interact with this vulnerability:\n")

	str.WriteString("\n#### 👍   Reply with this to acknowledge and accept the identified risk.\n")
	str.WriteString("```text\n")
	str.WriteString("/accept I accept the risk of this vulnerability, because ...\n")
	str.WriteString("```\n")

	str.WriteString("\n#### ⚠️ Mark the risk as false positive: Use one of these commands if you believe the reported vulnerability is not actually a valid issue.\n")

	str.WriteString("```text\n")
	str.WriteString("/component-not-present The vulnerable component is not included in the artifact.\n")
	str.WriteString("```\n")

	str.WriteString("```text\n")
	str.WriteString("/vulnerable-code-not-present The component is present, but the vulnerable code is not included or compiled.\n")
	str.WriteString("```\n")

	str.WriteString("```text\n")
	str.WriteString("/vulnerable-code-not-in-execute-path The vulnerable code exists, but is never executed at runtime.\n")
	str.WriteString("```\n")

	str.WriteString("```text\n")
	str.WriteString("/vulnerable-code-cannot-be-controlled-by-adversary Built-in protections prevent exploitation of this vulnerability.\n")
	str.WriteString("```\n")

	str.WriteString("```text\n")
	str.WriteString("/inline-mitigations-already-exist The vulnerable code cannot be controlled or influenced by an attacker.\n")
	str.WriteString("```\n")

	str.WriteString("\n#### 🔁  Reopen the risk: Use this command to reopen a previously closed or accepted vulnerability.\n")
	str.WriteString("```text\n")
	str.WriteString("/reopen ... \n")
	str.WriteString("```\n")

	return str
}
