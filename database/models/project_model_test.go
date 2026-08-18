package models

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestProjectSame(t *testing.T) {
	externalID := "14771"
	providerID := "opencode"
	id := uuid.New()

	t.Run("should return true for matching external identity", func(t *testing.T) {
		a := &Project{ExternalEntityID: &externalID, ExternalEntityProviderID: &providerID}
		b := &Project{ExternalEntityID: &externalID, ExternalEntityProviderID: &providerID}
		assert.True(t, a.Same(b))
	})

	t.Run("should not panic when other has no external identity", func(t *testing.T) {
		a := &Project{ExternalEntityID: &externalID, ExternalEntityProviderID: &providerID}
		b := &Project{Model: Model{ID: uuid.New()}}
		assert.NotPanics(t, func() { a.Same(b) })
		assert.False(t, a.Same(b))
	})

	t.Run("should fall back to id when neither has an external identity", func(t *testing.T) {
		a := &Project{Model: Model{ID: id}}
		b := &Project{Model: Model{ID: id}}
		assert.True(t, a.Same(b))
	})

	t.Run("should not panic when other is nil", func(t *testing.T) {
		a := &Project{ExternalEntityID: &externalID, ExternalEntityProviderID: &providerID}
		assert.NotPanics(t, func() { a.Same(nil) })
		assert.False(t, a.Same(nil))
	})
}
