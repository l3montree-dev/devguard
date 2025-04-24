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

	str.WriteString("\n#### ⚠️ Mark the risk as false positive: Use this command if you believe the reported vulnerability is not actually a valid issue.\n")
	str.WriteString("```text\n")
	str.WriteString("/false-positive We are not affected by this vulnerability, because ...\n")
	str.WriteString("```\n")

	str.WriteString("\n#### 🔁  Reopen the risk: Use this command to reopen a previously closed or accepted vulnerability.\n")
	str.WriteString("```text\n")
	str.WriteString("/reopen ... \n")
	str.WriteString("```\n")

	return str
}
