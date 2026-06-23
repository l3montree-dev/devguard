package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateTag(t *testing.T) {
	tests := []struct {
		input      string
		wantSemver string
		wantErr    bool
	}{
		{"v1.0.0", "1.0.0", false},
		{"v1.2.3", "1.2.3", false},
		{"v1.0.0-rc.1", "1.0.0-rc.1", false},
		{"v0.0.1-alpha.2", "0.0.1-alpha.2", false},
		{"1.0.0", "", true},
		{"v1.0", "", true},
		{"vfoo", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ValidateTag(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTag(%q) error=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}
			if got != tt.wantSemver {
				t.Errorf("ValidateTag(%q) = %q, want %q", tt.input, got, tt.wantSemver)
			}
		})
	}
}

func TestReplaceInFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("hello world\nhello again\n"), 0o644)

	changed, err := ReplaceInFile(path, "hello", "goodbye")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected changed=true")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "goodbye world\ngoodbye again\n" {
		t.Errorf("unexpected content: %q", got)
	}
}

func TestReplaceInFile_NoMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	original := "nothing to change here\n"
	os.WriteFile(path, []byte(original), 0o644)

	changed, err := ReplaceInFile(path, "nonexistent", "replacement")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("expected changed=false")
	}
	got, _ := os.ReadFile(path)
	if string(got) != original {
		t.Errorf("file was modified unexpectedly: %q", got)
	}
}

func TestReplaceLineInFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("line one\nline two\nline three\n"), 0o644)

	changed, err := ReplaceLineInFile(path, func(line string) string {
		if line == "line two" {
			return "LINE TWO"
		}
		return line
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected changed=true")
	}
	got, _ := os.ReadFile(path)
	want := "line one\nLINE TWO\nline three\n"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
