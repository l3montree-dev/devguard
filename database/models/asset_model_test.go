package models

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAssetSame(t *testing.T) {
	externalID := "12471"
	providerID := "opencode"
	otherExternalID := "99999"
	id := uuid.New()

	t.Run("should return true for matching external identity", func(t *testing.T) {
		a := &Asset{ExternalEntityID: &externalID, ExternalEntityProviderID: &providerID}
		b := &Asset{ExternalEntityID: &externalID, ExternalEntityProviderID: &providerID}
		assert.True(t, a.Same(b))
	})

	t.Run("should return false for different external identity", func(t *testing.T) {
		a := &Asset{ExternalEntityID: &externalID, ExternalEntityProviderID: &providerID}
		b := &Asset{ExternalEntityID: &otherExternalID, ExternalEntityProviderID: &providerID}
		assert.False(t, a.Same(b))
	})

	t.Run("should not panic when other has no external identity", func(t *testing.T) {
		a := &Asset{ExternalEntityID: &externalID, ExternalEntityProviderID: &providerID}
		b := &Asset{Model: Model{ID: uuid.New()}}
		assert.NotPanics(t, func() { a.Same(b) })
		assert.False(t, a.Same(b))
	})

	t.Run("should not panic when receiver has no external identity", func(t *testing.T) {
		a := &Asset{Model: Model{ID: uuid.New()}}
		b := &Asset{ExternalEntityID: &externalID, ExternalEntityProviderID: &providerID}
		assert.NotPanics(t, func() { a.Same(b) })
		assert.False(t, a.Same(b))
	})

	t.Run("should fall back to id when neither has an external identity", func(t *testing.T) {
		a := &Asset{Model: Model{ID: id}}
		b := &Asset{Model: Model{ID: id}}
		assert.True(t, a.Same(b))
	})

	t.Run("should return false for different ids without external identity", func(t *testing.T) {
		a := &Asset{Model: Model{ID: uuid.New()}}
		b := &Asset{Model: Model{ID: uuid.New()}}
		assert.False(t, a.Same(b))
	})

	t.Run("should not panic when other is nil", func(t *testing.T) {
		a := &Asset{ExternalEntityID: &externalID, ExternalEntityProviderID: &providerID}
		assert.NotPanics(t, func() { a.Same(nil) })
		assert.False(t, a.Same(nil))
	})

	t.Run("should not panic when receiver is nil", func(t *testing.T) {
		var a *Asset
		b := &Asset{Model: Model{ID: id}}
		assert.NotPanics(t, func() { a.Same(b) })
		assert.False(t, a.Same(b))
	})

	t.Run("should not panic when other has only one external field set", func(t *testing.T) {
		a := &Asset{ExternalEntityID: &externalID, ExternalEntityProviderID: &providerID}
		b := &Asset{ExternalEntityID: &externalID}
		assert.NotPanics(t, func() { a.Same(b) })
		assert.False(t, a.Same(b))
	})
}
