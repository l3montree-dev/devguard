package commands

import (
	"strings"
	"testing"
)

// Test that obfuscateString preserves tab characters when obfuscating
func TestObfuscateStringPreservesTabs(t *testing.T) {
	// prepare input containing a high-entropy "secret" token separated by tabs
	// we use a string with a likely high Shannon entropy (mix of letters and numbers)
	input := "prefix\tsecretTokenABC123xyz\tsuffix"

	out := obfuscateString(input)

	// ensure tabs are preserved
	if strings.Count(out, "\t") != strings.Count(input, "\t") {
		t.Fatalf("tabs were not preserved: expected %d tabs, got %d\ninput: %q\noutput: %q", strings.Count(input, "\t"), strings.Count(out, "\t"), input, out)
	}

	// ensure output still contains the prefix and suffix around the tabs
	partsIn := strings.Split(input, "\t")
	partsOut := strings.Split(out, "\t")
	if partsOut[0] != partsIn[0] {
		t.Fatalf("prefix changed: expected %q got %q", partsIn[0], partsOut[0])
	}
	if partsOut[2] != partsIn[2] {
		t.Fatalf("suffix changed: expected %q got %q", partsIn[2], partsOut[2])
	}

	// the middle part should be obfuscated: shorter or containing asterisks
	if partsOut[1] == partsIn[1] {
		t.Fatalf("middle token was not obfuscated: %q", partsOut[1])
	}
	if !strings.Contains(partsOut[1], "*") {
		t.Fatalf("expected obfuscated token to contain '*', got %q", partsOut[1])
	}
}

func TestObfuscateStringTable(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantContains string
		wantTabs     int
	}{
		{name: "preserve tabs", input: "prefix\tsecretTokenABC123xyz\tsuffix", wantContains: "prefix\t", wantTabs: 2},
		{name: "preserve spaces", input: "a b   c", wantContains: "a b   c", wantTabs: 0},
		{name: "newlines preserved", input: "line1\nsecretTOK123\nline3", wantContains: "line1\n", wantTabs: 0},
		{name: "obfuscate high entropy", input: "start ABCdefGhijkL12345 end", wantContains: "start ", wantTabs: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := obfuscateString(tt.input)

			// whitespace: tabs count
			if got := strings.Count(out, "\t"); got != tt.wantTabs {
				t.Fatalf("%s: unexpected tab count: want=%d got=%d\ninput:%q\noutput:%q", tt.name, tt.wantTabs, got, tt.input, out)
			}

			// ensure the expected substring (including whitespace) is present
			if !strings.Contains(out, tt.wantContains) {
				t.Fatalf("%s: output does not contain expected substring\ninput: %q\noutput: %q\nexpected substring: %q", tt.name, tt.input, out, tt.wantContains)
			}

			// for the high-entropy case ensure obfuscation occurred
			if tt.name == "obfuscate high entropy" {
				if out == tt.input {
					t.Fatalf("%s: expected obfuscation but output equals input", tt.name)
				}
			}
		})
	}
}
