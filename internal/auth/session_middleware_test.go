package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSessionMiddleware(t *testing.T) {
	t.Run("should set the correct scopes and userId using PAT-Auth", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		verifier := new(mocks.Verifier)
		verifier.On("VerifyRequestSignature", mock.Anything).Return("user1", "read write", nil)

		mw := SessionMiddleware(nil, verifier)

		var called bool
		handler := mw(func(ctx echo.Context) error {
			called = true
			sess := core.GetSession(ctx)

			assert.Equal(t, "user1", sess.GetUserID())
			assert.ElementsMatch(t, []string{"read", "write"}, sess.GetScopes())
			return nil
		})

		_ = handler(c)
		assert.True(t, called)
		verifier.AssertExpectations(t)
	})

	t.Run("should set no session, if pat auth fails, no admin token is used an no cookie is used.", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		verifier := new(mocks.Verifier)
		verifier.On("VerifyRequestSignature", mock.Anything).Return("", "", errors.New("fail"))

		mw := SessionMiddleware(nil, verifier)

		var called bool
		handler := mw(func(ctx echo.Context) error {
			called = true
			sess := core.GetSession(ctx)
			assert.Equal(t, NoSession, sess)
			return nil
		})

		_ = handler(c)
		assert.True(t, called)
		verifier.AssertExpectations(t)
	})

	t.Run("should set the correct scopes and userId using cookie auth", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// sat an ory_kratos_session cookie
		req.AddCookie(&http.Cookie{
			Name:  "ory_kratos_session",
			Value: "session_cookie_value",
		})

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAdminClient := mocks.NewAdminClient(t)
		mockAdminClient.On("GetIdentityFromCookie", mock.Anything, "ory_kratos_session=session_cookie_value").Return(client.Identity{
			ID: "user2",
		}, nil)

		mw := SessionMiddleware(mockAdminClient, nil)

		var called bool
		handler := mw(func(ctx echo.Context) error {
			called = true
			sess := core.GetSession(ctx)

			assert.Equal(t, "user2", sess.GetUserID())
			assert.ElementsMatch(t, []string{"scan", "manage"}, sess.GetScopes())
			return nil
		})

		_ = handler(c)
		assert.True(t, called)
	})

	t.Run("should set the session using admin token header", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Admin-Token", "admin_token_value")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mw := SessionMiddleware(nil, nil)

		var called bool
		handler := mw(func(ctx echo.Context) error {
			called = true
			sess := core.GetSession(ctx)

			assert.Equal(t, "admin_token_value", sess.GetUserID())
			assert.ElementsMatch(t, []string{}, sess.GetScopes())
			return nil
		})

		_ = handler(c)
		assert.True(t, called)
	})
}
