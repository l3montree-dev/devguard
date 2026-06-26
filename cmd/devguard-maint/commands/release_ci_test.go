package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceVersionDefault(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		from    string
		to      string
		want    string
		changed bool
	}{
		{
			name: "replaces default in version block",
			input: `inputs:
  version:
    default: "main"
    description: "scanner version"
  other:
    default: "main"
`,
			from: "main",
			to:   "v1.2.3",
			// only the default: inside the version: block should change
			want: `inputs:
  version:
    default: "v1.2.3"
    description: "scanner version"
  other:
    default: "main"
`,
			changed: true,
		},
		{
			name: "reverts tag back to main",
			input: `inputs:
  version:
    default: "v1.2.3"
    description: "scanner version"
`,
			from:    "v1.2.3",
			to:      "main",
			want:    "inputs:\n  version:\n    default: \"main\"\n    description: \"scanner version\"\n",
			changed: true,
		},
		{
			name: "no match returns unchanged",
			input: `inputs:
  version:
    default: "v9.9.9"
`,
			from:    "main",
			to:      "v1.2.3",
			want:    "inputs:\n  version:\n    default: \"v9.9.9\"\n",
			changed: false,
		},
		{
			name:    "no version block does not touch other defaults",
			input:   "other:\n  default: \"main\"\n",
			from:    "main",
			to:      "v1.2.3",
			want:    "other:\n  default: \"main\"\n",
			changed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "full.yml")
			if err := os.WriteFile(path, []byte(tt.input), 0o644); err != nil {
				t.Fatal(err)
			}

			changed, err := replaceVersionDefault(path, tt.from, tt.to)
			if err != nil {
				t.Fatal(err)
			}
			if changed != tt.changed {
				t.Errorf("changed=%v, want %v", changed, tt.changed)
			}
			got, _ := os.ReadFile(path)
			if string(got) != tt.want {
				t.Errorf("content mismatch\ngot:  %q\nwant: %q", got, tt.want)
			}
		})
	}
}
