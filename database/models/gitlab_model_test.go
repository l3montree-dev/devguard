package models

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestValidateGitLabOauth2TokenReservedUserID(t *testing.T) {
	token := &GitLabOauth2Token{
		UserID: "NO_SESSION",
	}

	err := validateGitLabOauth2Token(token)
	if err == nil {
		t.Fatalf("expected error for reserved user ID, got nil")
	}
	expected := fmt.Sprintf("cannot save token for user %s, this is a reserved user ID", "NO_SESSION")
	if err.Error() != expected {
		t.Errorf("unexpected error message: got %q, want %q", err.Error(), expected)
	}
}

func TestValidateGitLabOauth2TokenValidUserID(t *testing.T) {
	token := &GitLabOauth2Token{
		UserID: uuid.NewString(),
	}

	err := validateGitLabOauth2Token(token)
	if err != nil {
		t.Fatalf("expected no error for valid user ID, got: %v", err)
	}
}
