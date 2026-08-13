// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package tests

// Compares against controllers/ source directly (not docs/swagger.json), so
// a stale generated file can't mask a real mismatch. Handlers registered via
// a wrapping closure show up under an anonymous function name and are
// skipped rather than flagged.
import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var handlerNameRe = regexp.MustCompile(`([A-Za-z0-9_]+)\.\(\*([A-Za-z0-9_]+)\)\.([A-Za-z0-9_]+)-fm$`)

// Matches only a bare top-level function reference (pkg.FuncName), not a
// closure: closures add an enclosing-function segment (pkg.Outer.funcN),
// which the single-dot anchor here can't satisfy.
var plainFuncNameRe = regexp.MustCompile(`^.+/([A-Za-z0-9_]+)\.([A-Za-z_][A-Za-z0-9_]*)$`)
var routerAnnotationRe = regexp.MustCompile(`^@Router\s+(\S+)\s+\[(\w+)\]`)
var echoParamRe2 = regexp.MustCompile(`:([A-Za-z0-9_-]+)`)

// Matches a documented path's trailing named placeholder, e.g. ".../go/{path}"
// -> prefix ".../go". Used to reconcile echo's literal "*" wildcard tail
// (which OpenAPI has no syntax for) against a swag-valid "{name}" placeholder
// documenting the same tail-catch-all route.
var trailingParamRe = regexp.MustCompile(`^(.*)/\{[A-Za-z0-9_]+\}$`)

type routeEntry struct {
	method string
	path   string
}

// routeMatches treats a registered echo route ending in a literal "/*"
// wildcard as equivalent to a documented @Router path ending in "/{anything}"
// with the same prefix, since the two can't be spelled identically: echo's
// wildcard syntax and swag's OpenAPI path-param syntax are mutually
// exclusive ways of expressing the same catch-all tail.
func routeMatches(a, b routeEntry) bool {
	if a == b {
		return true
	}
	if a.method != b.method {
		return false
	}
	return isWildcardTailMatch(a, b) || isWildcardTailMatch(b, a)
}

func isWildcardTailMatch(reg, doc routeEntry) bool {
	if !strings.HasSuffix(reg.path, "/*") {
		return false
	}
	regPrefix := strings.TrimSuffix(reg.path, "/*")
	m := trailingParamRe.FindStringSubmatch(doc.path)
	if m == nil {
		return false
	}
	return regPrefix == m[1]
}

func normalizeRoutePath(p string) string {
	if p != "/" {
		p = strings.TrimSuffix(p, "/")
	}
	if p == "" {
		p = "/"
	}
	return p
}

func echoPathToOpenAPI(p string) string {
	p = strings.TrimPrefix(p, "/api/v1")
	p = echoParamRe2.ReplaceAllString(p, "{$1}")
	return normalizeRoutePath(p)
}

func handlerKeyFromRouteName(name string) string {
	if m := handlerNameRe.FindStringSubmatch(name); m != nil {
		return m[1] + "." + m[2] + "." + m[3]
	}
	if m := plainFuncNameRe.FindStringSubmatch(name); m != nil {
		return m[1] + "." + m[2]
	}
	return ""
}

func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// Keyed by "<package>.<ReceiverType>.<MethodName>" to match
// handlerKeyFromRouteName's derivation from echo's runtime handler name.
func parseControllerRouterAnnotations(t *testing.T, root string) map[string][]routeEntry {
	t.Helper()
	result := map[string][]routeEntry{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		pkgDir := filepath.Base(filepath.Dir(path))
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Doc == nil {
				continue
			}

			var key string
			if fn.Recv == nil {
				key = pkgDir + "." + fn.Name.Name
			} else if recvType := receiverTypeName(fn.Recv); recvType != "" {
				key = pkgDir + "." + recvType + "." + fn.Name.Name
			} else {
				continue
			}

			for _, c := range fn.Doc.List {
				text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				m := routerAnnotationRe.FindStringSubmatch(text)
				if m == nil {
					continue
				}
				result[key] = append(result[key], routeEntry{
					method: strings.ToUpper(m[2]),
					path:   normalizeRoutePath(m[1]),
				})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to parse controllers for @Router annotations: %v", err)
	}
	return result
}

func TestOpenAPIRouterAnnotationsMatchRoutes(t *testing.T) {
	e, _ := buildFullRouterServer(t, true)

	routes := e.Routes()
	registered := map[string]map[routeEntry]bool{}
	var unverifiable []string
	syntheticCount := 0

	for _, route := range routes {
		// Echo always carries this synthetic entry for its internal 404 fallback;
		// it isn't a route anyone registered, so there's no @Router to check it against.
		if route.Method == "echo_route_not_found" {
			syntheticCount++
			continue
		}
		key := handlerKeyFromRouteName(route.Name)
		if key == "" {
			unverifiable = append(unverifiable, fmt.Sprintf("%s %s (handler=%s)", route.Method, route.Path, route.Name))
			continue
		}
		entry := routeEntry{method: route.Method, path: echoPathToOpenAPI(route.Path)}
		if registered[key] == nil {
			registered[key] = map[routeEntry]bool{}
		}

		registered[key][entry] = true
	}

	documented := parseControllerRouterAnnotations(t, "../controllers")

	var problems []string

	for key, routes := range registered {
		docs := documented[key]
		for r := range routes {
			found := false
			for _, d := range docs {
				if routeMatches(r, d) {
					found = true
					break
				}
			}
			if !found {
				problems = append(problems, fmt.Sprintf(
					"%s: registered route %s %s has no matching @Router annotation",
					key, r.method, r.path))
			}
		}
	}

	for key, routes := range documented {
		regs := registered[key]
		for _, r := range routes {
			found := false
			for reg := range regs {
				if routeMatches(reg, r) {
					found = true
					break
				}
			}
			if !found {
				problems = append(problems, fmt.Sprintf(
					"%s: @Router annotation %s %s does not match any registered route",
					key, r.method, r.path))
			}
		}
	}

	sort.Strings(problems)
	sort.Strings(unverifiable)

	checked := 0
	for _, entries := range registered {
		checked += len(entries)
	}
	t.Logf("openapi coverage: %d routes total, %d synthetic (echo_route_not_found), %d checked against @Router annotations, %d with no traceable handler",
		len(routes), syntheticCount, checked, len(unverifiable))

	if len(unverifiable) > 0 {
		problems = append(problems, fmt.Sprintf(
			"%d route(s) have a handler that isn't a direct controller method (closure/anonymous func), so their @Router annotation could not be verified automatically - check them by hand:\n\t%s",
			len(unverifiable), strings.Join(unverifiable, "\n\t")))
		t.Errorf("openapi @Router annotation verification incomplete: %d unverifiable route(s)", len(unverifiable))

	}

	if len(problems) > 0 {
		t.Errorf("openapi @Router annotations are out of sync with actual route registrations:\n%s",
			strings.Join(problems, "\n"))
	}
}
