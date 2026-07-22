package middlewares

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newConfigMock(t *testing.T, settings shared.InstanceSettings) *mocks.ConfigService {
	t.Helper()
	cs := mocks.NewConfigService(t)
	cs.On("GetInstanceSettings", mock.Anything).Return(settings, nil)
	return cs
}

func TestSessionMiddleware(t *testing.T) {
	t.Run("should set the correct scopes and userID using PAT-Auth", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		verifier := new(mocks.Authorizer)
		verifier.On("VerifyRequestSignature", mock.Anything, mock.Anything).Return(shared.NewSession("user1", shared.SessionActorUser, []string{"read", "write"}, false), nil)

		mw := SessionMiddleware(nil, newConfigMock(t, shared.InstanceSettings{}), verifier)

		var called bool
		handler := mw(func(ctx echo.Context) error {
			called = true
			sess := shared.GetSession(ctx)
			assert.Equal(t, "user1", sess.GetActorID())
			assert.ElementsMatch(t, []string{"read", "write"}, sess.GetScopes())
			return nil
		})

		_ = handler(c)
		assert.True(t, called)
		verifier.AssertExpectations(t)
	})

	t.Run("should set no session when request signature verification fails", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		verifier := new(mocks.Authorizer)
		verifier.On("VerifyRequestSignature", mock.Anything, mock.Anything).Return(nil, errors.New("could not verify request"))

		mw := SessionMiddleware(nil, newConfigMock(t, shared.InstanceSettings{}), verifier)

		var called bool
		handler := mw(func(ctx echo.Context) error {
			called = true
			sess := shared.GetSession(ctx)
			assert.Equal(t, shared.NoSession, sess)
			return nil
		})

		_ = handler(c)
		assert.True(t, called)
		verifier.AssertExpectations(t)
	})

	t.Run("should set the correct scopes and userID using Bearer token auth", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer mytoken123")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		verifier := new(mocks.Authorizer)
		verifier.On("VerifyAPIToken", mock.Anything, "mytoken123").Return(shared.NewSession("user3", shared.SessionActorUser, []string{"scan"}, false), nil)

		mw := SessionMiddleware(nil, newConfigMock(t, shared.InstanceSettings{}), verifier)

		var called bool
		handler := mw(func(ctx echo.Context) error {
			called = true
			sess := shared.GetSession(ctx)
			assert.Equal(t, "user3", sess.GetActorID())
			assert.ElementsMatch(t, []string{"scan"}, sess.GetScopes())
			return nil
		})

		_ = handler(c)
		assert.True(t, called)
		verifier.AssertExpectations(t)
	})

	t.Run("should set no session when Bearer token verification fails", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer badtoken")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		verifier := new(mocks.Authorizer)
		verifier.On("VerifyAPIToken", mock.Anything, "badtoken").Return(nil, errors.New("invalid token"))

		mw := SessionMiddleware(nil, newConfigMock(t, shared.InstanceSettings{}), verifier)

		var called bool
		handler := mw(func(ctx echo.Context) error {
			called = true
			sess := shared.GetSession(ctx)
			assert.Equal(t, shared.NoSession, sess)
			return nil
		})

		_ = handler(c)
		assert.True(t, called)
		verifier.AssertExpectations(t)
	})

	t.Run("should skip Bearer token auth and fall back to request signature when BearerTokenAuthDisabled", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer mytoken123")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		verifier := new(mocks.Authorizer)
		verifier.On("VerifyRequestSignature", mock.Anything, mock.Anything).Return(shared.NewSession("user5", shared.SessionActorUser, []string{"read"}, false), nil)

		mw := SessionMiddleware(nil, newConfigMock(t, shared.InstanceSettings{BearerTokenAuthDisabled: true}), verifier)

		var called bool
		handler := mw(func(ctx echo.Context) error {
			called = true
			sess := shared.GetSession(ctx)
			assert.Equal(t, "user5", sess.GetActorID())
			return nil
		})

		_ = handler(c)
		assert.True(t, called)
		verifier.AssertExpectations(t)
	})

	t.Run("should fall through to request signature when cookie auth fails", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "ory_kratos_session",
			Value: "bad_cookie",
		})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAdminClient := mocks.NewPublicClient(t)
		mockAdminClient.On("GetIdentityFromCookie", mock.Anything, "ory_kratos_session=bad_cookie").Return(client.Identity{}, errors.New("invalid cookie"))

		verifier := new(mocks.Authorizer)
		verifier.On("VerifyRequestSignature", mock.Anything, mock.Anything).Return(shared.NewSession("user4", shared.SessionActorUser, []string{"read"}, false), nil)

		mw := SessionMiddleware(mockAdminClient, newConfigMock(t, shared.InstanceSettings{}), verifier)

		var called bool
		handler := mw(func(ctx echo.Context) error {
			called = true
			sess := shared.GetSession(ctx)
			assert.Equal(t, "user4", sess.GetActorID())
			return nil
		})

		_ = handler(c)
		assert.True(t, called)
		verifier.AssertExpectations(t)
	})

	t.Run("should set the correct scopes and userID using cookie auth", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "ory_kratos_session",
			Value: "session_cookie_value",
		})

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAdminClient := mocks.NewPublicClient(t)
		mockAdminClient.On("GetIdentityFromCookie", mock.Anything, "ory_kratos_session=session_cookie_value").Return(client.Identity{
			Id: "user2",
		}, nil)

		mw := SessionMiddleware(mockAdminClient, newConfigMock(t, shared.InstanceSettings{}), nil)

		var called bool
		handler := mw(func(ctx echo.Context) error {
			called = true
			sess := shared.GetSession(ctx)
			assert.Equal(t, "user2", sess.GetActorID())
			assert.ElementsMatch(t, []string{"scan", "manage"}, sess.GetScopes())
			return nil
		})

		_ = handler(c)
		assert.True(t, called)
	})
}
