package dtos_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/dtos"
	"gopkg.in/yaml.v3"
)

func TestNpmRegistryConfigsForPackage(t *testing.T) {
	configs := dtos.NpmRegistryConfigs{
		{URLRegistryConfig: dtos.URLRegistryConfig{URL: "https://npm.firma.de"}, Scopes: []string{"@firma"}, Auth: &dtos.RegistryAuth{Type: "token", Token: "secret"}},
		{URLRegistryConfig: dtos.URLRegistryConfig{URL: "https://fallback.de"}},
	}

	t.Run("uses the registry of a matching scope", func(t *testing.T) {
		config := configs.ForPackage("@firma/utils")
		if config.URL != "https://npm.firma.de" || config.Auth.Token != "secret" {
			t.Fatalf("expected firma registry with token, got %+v", config)
		}
	})

	t.Run("uses the fallback for unscoped and unknown scoped packages", func(t *testing.T) {
		for _, name := range []string{"next", "@vercel/og"} {
			if url := configs.ForPackage(name).URL; url != "https://fallback.de" {
				t.Fatalf("expected fallback for %s, got %s", name, url)
			}
		}
	})

	t.Run("uses npmjs if there is no fallback", func(t *testing.T) {
		if url := configs[:1].ForPackage("next").URL; url != "https://registry.npmjs.org" {
			t.Fatalf("expected npmjs, got %s", url)
		}
	})
}

func TestDependencyProxyConfigNpmRegistries(t *testing.T) {
	t.Run("rejects the legacy string format", func(t *testing.T) {
		var cfg dtos.DependencyProxyConfig
		if err := yaml.Unmarshal([]byte("registries:\n  npm: https://npm.firma.de\n"), &cfg); err == nil {
			t.Fatal("expected an error for the legacy string format")
		}
	})

	t.Run("accepts a list of registries with token and login auth", func(t *testing.T) {
		content := "registries:\n  npm:\n    - url: https://npm.firma.de\n      scopes: [\"@firma\"]\n      auth:\n        type: token\n        token: $npm_token\n    - url: https://nexus.firma.de\n      auth:\n        type: basic-auth\n        username: ci-user\n        password: $nexus_password\n"
		if err := dtos.ValidateDependencyProxyConfigFile([]byte(content)); err != nil {
			t.Fatalf("expected valid, got %v", err)
		}
	})

	t.Run("rejects invalid entries", func(t *testing.T) {
		for _, content := range []string{
			"registries:\n  npm:\n    - url: not-a-url\n",
			"registries:\n  npm:\n    - url: https://npm.firma.de\n      scopes: [\"firma\"]\n",
			"registries:\n  npm:\n    - url: https://npm.firma.de\n      auth:\n        token: $npm_token\n",
			"registries:\n  npm:\n    - url: https://npm.firma.de\n      auth:\n        type: token\n",
			"registries:\n  npm:\n    - url: https://npm.firma.de\n      auth:\n        type: token\n        token: plaintext\n",
			"registries:\n  npm:\n    - url: https://npm.firma.de\n      auth:\n        type: login\n        username: ci-user\n",
		} {
			if err := dtos.ValidateDependencyProxyConfigFile([]byte(content)); err == nil {
				t.Fatalf("expected validation error for %q", content)
			}
		}
	})
}

func TestDependencyProxyConfigMavenRegistry(t *testing.T) {
	t.Run("parses the legacy string format", func(t *testing.T) {
		var cfg dtos.DependencyProxyConfig
		if err := yaml.Unmarshal([]byte("registries:\n  maven: https://nexus.firma.de\n"), &cfg); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		maven := cfg.Registries.MavenConfig()
		if maven == nil || maven.URL != "https://nexus.firma.de" || maven.Auth != nil {
			t.Fatalf("expected legacy registry without auth, got %+v", maven)
		}
	})

	t.Run("accepts a registry with login auth", func(t *testing.T) {
		content := "registries:\n  maven:\n    url: https://nexus.firma.de\n    auth:\n      type: basic-auth\n      username: ci-user\n      password: $nexus_password\n"
		if err := dtos.ValidateDependencyProxyConfigFile([]byte(content)); err != nil {
			t.Fatalf("expected valid, got %v", err)
		}
	})

	t.Run("rejects invalid entries", func(t *testing.T) {
		for _, content := range []string{
			"registries:\n  maven:\n    url: not-a-url\n",
			"registries:\n  maven:\n    url: https://nexus.firma.de\n    auth:\n      type: token\n      token: plaintext\n",
			"registries:\n  maven:\n    url: https://nexus.firma.de\n    auth:\n      type: login\n      username: ci-user\n",
		} {
			if err := dtos.ValidateDependencyProxyConfigFile([]byte(content)); err == nil {
				t.Fatalf("expected validation error for %q", content)
			}
		}
	})
}
