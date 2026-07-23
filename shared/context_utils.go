// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
package shared

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"go.opentelemetry.io/otel/trace"

	"github.com/l3montree-dev/devguard/utils"
	"github.com/ory/client-go"
)

// ctxKey* constants are the only string literals used to key values into
// shared.Context (echo.Context.Get/Set). They must not be used directly
// outside this file - every other package reads/writes context values through
// the accessor functions below (GetX/SetX/MaybeGetX), so a rename or type
// change here can never silently desync from a copy-pasted literal elsewhere.
const (
	ctxKeyThirdPartyIntegration = "thirdPartyIntegration"
	ctxKeyAuthAdminClient       = "authAdminClient"
	ctxKeyRBAC                  = "rbac"
	ctxKeyOrg                   = "org"
	ctxKeyOrgSlug               = "orgSlug"
	ctxKeyProject               = "project"
	ctxKeyProjectSlug           = "projectSlug"
	ctxKeyAsset                 = "asset"
	ctxKeyAssetSlug             = "assetSlug"
	ctxKeyAssetVersion          = "assetVersion"
	ctxKeyPublicRequest         = "publicRequest"
	ctxKeySession               = "session"
	ctxKeyActorScope            = "actorScope"
	ctxKeyArtifact              = "artifact"
	ctxKeyEventID               = "eventID"
	ctxKeyProviderID            = "providerID"
	ctxKeyDependencyVulnID      = "dependencyVulnID"
	ctxKeyFirstPartyVulnID      = "firstPartyVulnID"
	ctxKeyLicenseRiskID         = "licenseRiskID"
)

func GetThirdPartyIntegration(ctx Context) IntegrationAggregate {
	return ctx.Get(ctxKeyThirdPartyIntegration).(IntegrationAggregate)
}

func SetThirdPartyIntegration(ctx Context, i IntegrationAggregate) {
	ctx.Set(ctxKeyThirdPartyIntegration, i)
}

func MaybeGetThirdPartyIntegration(ctx Context) (IntegrationAggregate, bool) {
	i, ok := ctx.Get(ctxKeyThirdPartyIntegration).(IntegrationAggregate)
	return i, ok
}

type AdminClient interface {
	ListUser(client client.IdentityAPIListIdentitiesRequest) ([]client.Identity, error)
	GetIdentity(ctx context.Context, userID string) (client.Identity, error)
	GetIdentityWithCredentials(ctx context.Context, userID string) (client.Identity, error)
}

type PublicClient interface {
	GetIdentityFromCookie(ctx context.Context, cookie string) (client.Identity, error)
}

type PublicClientImplementation struct {
	apiClient *client.APIClient
}

func NewPublicClient(client *client.APIClient) PublicClientImplementation {
	return PublicClientImplementation{
		apiClient: client,
	}
}

type AdminClientImplementation struct {
	apiClient *client.APIClient
}

func NewAdminClient(client *client.APIClient) AdminClientImplementation {
	return AdminClientImplementation{
		apiClient: client,
	}
}

func (a PublicClientImplementation) GetIdentityFromCookie(ctx context.Context, cookie string) (client.Identity, error) {
	session, _, err := a.apiClient.FrontendAPI.ToSession(ctx).Cookie(cookie).Execute()
	if err != nil {
		return client.Identity{}, fmt.Errorf("could not get identity from cookie: %w", err)
	}
	if session.Identity == nil {
		return client.Identity{}, fmt.Errorf("identity not found in session")
	}
	return *session.Identity, nil
}

func (a AdminClientImplementation) ListUser(request client.IdentityAPIListIdentitiesRequest) ([]client.Identity, error) {
	clients, _, err := a.apiClient.IdentityAPI.ListIdentitiesExecute(request)
	return clients, err
}

func (a AdminClientImplementation) GetIdentityWithCredentials(ctx context.Context, userID string) (client.Identity, error) {
	resp, _, err := a.apiClient.IdentityAPI.GetIdentity(ctx, userID).IncludeCredential([]string{"oidc"}).Execute()
	if err != nil {
		return client.Identity{}, err
	}
	return *resp, nil
}

func (a AdminClientImplementation) GetIdentity(ctx context.Context, userID string) (client.Identity, error) {
	request, _, err := a.apiClient.IdentityAPI.GetIdentity(ctx, userID).Execute()
	if err != nil {
		return *request, err
	}
	return *request, nil
}

func SetAuthAdminClient(ctx Context, i AdminClient) {
	ctx.Set(ctxKeyAuthAdminClient, i)
}

func GetAuthAdminClient(ctx Context) AdminClient {
	return ctx.Get(ctxKeyAuthAdminClient).(AdminClient)
}

func MaybeGetAuthAdminClient(ctx Context) (AdminClient, bool) {
	i, ok := ctx.Get(ctxKeyAuthAdminClient).(AdminClient)
	return i, ok
}

func GetVulnID(ctx Context) (uuid.UUID, dtos.VulnType, error) {
	dependencyVulnID := ctx.Param(ctxKeyDependencyVulnID)
	if dependencyVulnID != "" {
		id, err := uuid.Parse(dependencyVulnID)
		if err != nil {
			return uuid.Nil, "", fmt.Errorf("invalid dependency vuln id: %w", err)
		}
		return id, dtos.VulnTypeDependencyVuln, nil
	}
	dependencyVulnIDFromGet, ok := ctx.Get(ctxKeyDependencyVulnID).(string)
	if ok && dependencyVulnIDFromGet != "" {
		id, err := uuid.Parse(dependencyVulnIDFromGet)
		if err != nil {
			return uuid.Nil, "", fmt.Errorf("invalid dependency vuln id: %w", err)
		}
		return id, dtos.VulnTypeDependencyVuln, nil
	}

	firstPartyVulnID := ctx.Param(ctxKeyFirstPartyVulnID)
	if firstPartyVulnID != "" {
		id, err := uuid.Parse(firstPartyVulnID)
		if err != nil {
			return uuid.Nil, "", fmt.Errorf("invalid first party vuln id: %w", err)
		}
		return id, dtos.VulnTypeFirstPartyVuln, nil
	}
	firstPartyVulnIDFromGet, ok := ctx.Get(ctxKeyFirstPartyVulnID).(string)
	if ok && firstPartyVulnIDFromGet != "" {
		id, err := uuid.Parse(firstPartyVulnIDFromGet)
		if err != nil {
			return uuid.Nil, "", fmt.Errorf("invalid first party vuln id: %w", err)
		}
		return id, dtos.VulnTypeFirstPartyVuln, nil
	}

	licenseRiskID := ctx.Param(ctxKeyLicenseRiskID)
	if licenseRiskID != "" {
		id, err := uuid.Parse(licenseRiskID)
		if err != nil {
			return uuid.Nil, "", fmt.Errorf("invalid license risk id: %w", err)
		}
		return id, dtos.VulnTypeLicenseRisk, nil
	}
	licenseRiskIDFromGet, ok := ctx.Get(ctxKeyLicenseRiskID).(string)
	if ok && licenseRiskIDFromGet != "" {
		id, err := uuid.Parse(licenseRiskIDFromGet)
		if err != nil {
			return uuid.Nil, "", fmt.Errorf("invalid license risk id: %w", err)
		}
		return id, dtos.VulnTypeLicenseRisk, nil
	}

	return uuid.Nil, "", fmt.Errorf("could not get vuln id")
}

func SetRBAC(ctx Context, rbac AccessControl) {
	ctx.Set(ctxKeyRBAC, rbac)
}

func MaybeGetRBAC(ctx Context) (AccessControl, bool) {
	rbac, ok := ctx.Get(ctxKeyRBAC).(AccessControl)
	return rbac, ok
}

// SetOrg/GetOrg use the ctxKeyOrg key, deliberately distinct from ctxKeyOrgSlug
// - the latter is the raw org slug (URL path param or header-injected override,
// see AssetNameMiddleware) that GetParam reads. Reusing one key for both the
// string slug and the resolved model would make GetParam's fallback return the
// wrong type depending on call order.
func SetOrg(c Context, org models.Org) {
	c.Set(ctxKeyOrg, org)
}

func SetOrgSlug(ctx Context, orgSlug string) {
	ctx.Set(ctxKeyOrgSlug, orgSlug)
}

func GetOrg(c Context) models.Org {
	return c.Get(ctxKeyOrg).(models.Org)
}

func HasOrganization(c Context) bool {
	_, ok := c.Get(ctxKeyOrg).(models.Org)
	return ok
}
func HasProject(c Context) bool {
	_, ok := c.Get(ctxKeyProject).(models.Project)
	return ok
}
func GetRBAC(ctx Context) AccessControl {
	return ctx.Get(ctxKeyRBAC).(AccessControl)
}

func SetIsPublicRequest(ctx Context) {
	ctx.Set(ctxKeyPublicRequest, true)
}

func IsPublicRequest(ctx Context) bool {
	return ctx.Get(ctxKeyPublicRequest) != nil
}

func GetSession(ctx Context) AuthSession {
	return ctx.Get(ctxKeySession).(AuthSession)
}

func SetSession(ctx Context, session AuthSession) {
	ctx.Set(ctxKeySession, session)
}

func MaybeGetSession(ctx Context) (AuthSession, bool) {
	session, ok := ctx.Get(ctxKeySession).(AuthSession)
	return session, ok
}

func GetParam(ctx Context, param string) string {
	if v, ok := ctx.Get(param).(string); ok {
		return v
	}
	return ctx.Param(param)
}

func GetURLDecodedParam(ctx Context, param string) (string, error) {
	v := GetParam(ctx, param)
	decoded, err := url.QueryUnescape(v)
	if err != nil {
		return "", fmt.Errorf("could not url decode param %s: %w", param, err)
	}
	return decoded, nil
}

func GetProjectSlug(ctx Context) (string, error) {
	projectID := GetParam(ctx, ctxKeyProjectSlug)
	if projectID == "" {
		return "", fmt.Errorf("could not get project id")
	}
	return projectID, nil
}

func GetOrgSlug(ctx Context) (string, error) {
	orgSlug := GetParam(ctx, ctxKeyOrgSlug)
	if orgSlug == "" {
		return "", fmt.Errorf("could not get org slug")
	}
	return orgSlug, nil
}

func SetProjectSlug(ctx Context, projectSlug string) {
	ctx.Set(ctxKeyProjectSlug, projectSlug)
}

func SetAssetSlug(ctx Context, assetSlug string) {
	ctx.Set(ctxKeyAssetSlug, assetSlug)
}

func SetArtifact(ctx Context, artifact models.Artifact) {
	ctx.Set(ctxKeyArtifact, artifact)
}

func GetArtifact(ctx Context) models.Artifact {
	return ctx.Get(ctxKeyArtifact).(models.Artifact)
}

// MaybeGetArtifact tolerates the artifact being stored as either a value or a
// pointer, since some webhook/event call sites set a *models.Artifact.
func MaybeGetArtifact(ctx Context) (models.Artifact, error) {
	val := ctx.Get(ctxKeyArtifact)
	if val == nil {
		return models.Artifact{}, fmt.Errorf("artifact not found in context")
	}
	if artifact, ok := val.(*models.Artifact); ok {
		return *artifact, nil
	}
	if artifact, ok := val.(models.Artifact); ok {
		return artifact, nil
	}
	return models.Artifact{}, fmt.Errorf("artifact context value has unexpected type %T", val)
}

func GetArtifactName(ctx Context) (string, error) {
	artifactName := GetParam(ctx, "artifactName")
	if artifactName == "" {
		return "", fmt.Errorf("could not get artifact name")
	}
	// urldecode the artifact name
	artifactName, err := url.PathUnescape(artifactName)

	if err != nil {
		return "", fmt.Errorf("could not url decode artifact name: %w", err)
	}
	return artifactName, nil
}

func GetAssetSlug(ctx Context) (string, error) {
	assetSlug := GetParam(ctx, ctxKeyAssetSlug)
	if assetSlug == "" {
		return "", fmt.Errorf("could not get asset slug")
	}
	return assetSlug, nil
}

func GetAssetVersionSlug(ctx Context) (string, error) {
	assetVersionSlug := GetParam(ctx, "assetVersionSlug")
	if assetVersionSlug == "" {
		return "", fmt.Errorf("could not get asset version slug")
	}
	return assetVersionSlug, nil
}

func GetAsset(ctx Context) models.Asset {
	return ctx.Get(ctxKeyAsset).(models.Asset)
}

func SetAsset(ctx Context, asset models.Asset) {
	ctx.Set(ctxKeyAsset, asset)
}

// SetActorScope/GetActorScope carry the session's own scoped entity (as opposed
// to the URL-resolved project/asset set via SetProject/SetAsset), pre-resolved
// once by ResourceFetchMiddleware from the session's owner ID.
func SetActorScope(ctx Context, scope ActorScope) {
	ctx.Set(ctxKeyActorScope, scope)
}

func GetActorScope(ctx Context) ActorScope {
	scope, _ := ctx.Get(ctxKeyActorScope).(ActorScope)
	return scope
}

func GetAssetVersion(ctx Context) models.AssetVersion {
	return ctx.Get(ctxKeyAssetVersion).(models.AssetVersion)
}

func MaybeGetOrganization(ctx Context) (models.Org, error) {
	org, ok := ctx.Get(ctxKeyOrg).(models.Org)
	if !ok {
		return models.Org{}, fmt.Errorf("could not get organization")
	}
	return org, nil
}

func MaybeGetProject(ctx Context) (models.Project, error) {
	project, ok := ctx.Get(ctxKeyProject).(models.Project)
	if !ok {
		return models.Project{}, fmt.Errorf("could not get project")
	}
	return project, nil
}

func MaybeGetAsset(ctx Context) (models.Asset, error) {
	asset, ok := ctx.Get(ctxKeyAsset).(models.Asset)
	if !ok {
		return models.Asset{}, fmt.Errorf("could not get asset")
	}
	return asset, nil
}

func MaybeGetAssetVersion(ctx Context) (models.AssetVersion, error) {
	assetVersion, ok := ctx.Get(ctxKeyAssetVersion).(models.AssetVersion)
	if !ok {
		return models.AssetVersion{}, fmt.Errorf("could not get asset version")
	}
	return assetVersion, nil
}

func SetAssetVersion(ctx Context, assetVersion models.AssetVersion) {
	ctx.Set(ctxKeyAssetVersion, assetVersion)
}

func GetEventID(ctx Context) (string, error) {
	eventID := ctx.Param(ctxKeyEventID)
	if eventID == "" {
		return "", fmt.Errorf("could not get event id")
	}
	return eventID, nil
}

func SetEventID(ctx Context, eventID string) {
	ctx.Set(ctxKeyEventID, eventID)
}

func SetProject(ctx Context, project models.Project) {
	ctx.Set(ctxKeyProject, project)
}

func GetProject(ctx Context) models.Project {
	return ctx.Get(ctxKeyProject).(models.Project)
}

func SetProviderID(ctx Context, providerID string) {
	ctx.Set(ctxKeyProviderID, providerID)
}

func GetProviderID(ctx Context) string {
	v, _ := ctx.Get(ctxKeyProviderID).(string)
	return v
}

func GetRepositoryID(asset *models.Asset) (string, error) {
	if asset.RepositoryID != nil {
		return *asset.RepositoryID, nil
	}
	if asset.ExternalEntityID != nil {
		return *asset.ExternalEntityID, nil
	}

	return "", fmt.Errorf("could not get repository id from asset")
}

type PageInfo struct {
	PageSize int `json:"pageSize"`
	Page     int `json:"page"`
}

func (p PageInfo) ApplyOnDB(db DB) DB {
	return db.Offset((p.Page - 1) * p.PageSize).Limit(p.PageSize)
}

type Paged[T any] struct {
	PageInfo
	Total int64 `json:"total"`
	Data  []T   `json:"data"`
}

func (p Paged[T]) Map(f func(T) any) Paged[any] {
	data := make([]any, len(p.Data))
	for i, d := range p.Data {
		data[i] = f(d)
	}
	return Paged[any]{
		PageInfo: p.PageInfo,
		Total:    p.Total,
		Data:     data,
	}
}

func NewPaged[T any](pageInfo PageInfo, total int64, data []T) Paged[T] {
	return Paged[T]{
		PageInfo: pageInfo,
		Total:    total,
		Data:     data,
	}
}

func GetPageInfo(ctx Context) PageInfo {
	page, _ := strconv.Atoi(ctx.QueryParam("page"))
	if page <= 0 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(ctx.QueryParam("pageSize"))
	switch {
	case pageSize > 100:
		pageSize = 100
	case pageSize <= 0:
		pageSize = 10
	}

	return PageInfo{
		Page:     page,
		PageSize: pageSize,
	}
}

type FilterQuery struct {
	Field      string
	FieldValue any
	Operator   string
}

func GetFilterQuery(ctx Context) []FilterQuery {
	// get all query params, which start with filterQuery
	query := ctx.QueryParams()
	filterQuerys := []FilterQuery{}
	for key := range query {
		if !strings.HasPrefix(key, "filterQuery") {
			continue
		}

		// get the value
		value := query.Get(key)
		// extract the field and operator from the key
		// it looks like this: filterQuery[cve.cvss][is]=10

		// remove the filterQuery prefix
		key = strings.TrimPrefix(key, "filterQuery")
		// use a regex
		// get the field
		field := strings.Split(key, "[")[1]
		field = strings.TrimSuffix(field, "]")

		// get the operator
		operator := strings.Split(key, "[")[2]
		operator = strings.TrimSuffix(operator, "]")

		filterQuerys = append(filterQuerys, FilterQuery{
			Field:      field,
			FieldValue: value,
			Operator:   operator,
		})
	}

	return filterQuerys
}

type SortQuery struct {
	Field    string
	Operator string // asc or desc
}

func GetSortQuery(ctx Context) []SortQuery {
	// get all query params, which start with filterQuery
	query := ctx.QueryParams()
	sortQuerys := []SortQuery{}
	for key := range query {
		if !strings.HasPrefix(key, "sort") {
			continue
		}

		// get the value
		operator := query.Get(key)
		// extract the field and operator from the key
		// it looks like this: sort[cve.cvss]=desc

		// remove the filterQuery prefix
		key = strings.TrimPrefix(key, "sort")
		// use a regex
		// get the field
		field := strings.Split(key, "[")[1]
		field = strings.TrimSuffix(field, "]")

		sortQuerys = append(sortQuerys, SortQuery{
			Field:    field,
			Operator: operator,
		})
	}

	return sortQuerys
}

func quoteFields(field string) string {
	// split at the dot
	split := strings.Split(field, ".")
	quotedSplits := utils.Map(
		split,
		func(s string) string {
			return fmt.Sprintf(`"%s"`, s)
		},
	)

	return strings.Join(quotedSplits, ".")
}

// Regular expression to validate field names
var validFieldNameRegex = regexp.MustCompile("^[a-zA-Z0-9_.]+$")

func sanitizeField(field string) string {
	if !validFieldNameRegex.MatchString(field) {
		panic("invalid field name - to risky, might be sql injection")
	}

	return quoteFields(field)
}

func (f FilterQuery) SQL() string {

	field := sanitizeField(f.Field)

	switch f.Operator {
	case "in":
		return field + " IN (?)"
	case "is":
		return field + " = ?"
	case "is not":
		return field + " != ?"
	case "is greater than":
		return field + " > ?"
	case "is less than":
		return field + " < ?"
	case "is after":
		return field + " > ?"
	case "is before":
		return field + " < ?"
	case "like":
		return field + " LIKE ?"
	case "ilike":
		return field + " ILIKE ?"
	case "any":
		return "? = ANY(string_to_array(" + field + ", ' '))"
	default:
		// default do an equals
		return field + " = ?"
	}

}

func (f FilterQuery) Value() any {
	// convert the value to the correct type
	switch f.Operator {
	default:
		return f.FieldValue
	}
}

func (s SortQuery) SQL() string {
	// Regular expression to validate field names
	validFieldNameRegex := regexp.MustCompile("^[a-zA-Z0-9_.]+$")

	if !validFieldNameRegex.MatchString(s.Field) {
		panic("invalid field name - to risky, might be sql injection")
	}

	field := sanitizeField(s.Field)

	switch s.Operator {
	case "asc":
		return field + " asc"
	case "desc":
		return field + " desc NULLS LAST"
	default:
		// default do an equals
		return field + " asc NULLS LAST"
	}
}

func (s SortQuery) GetField() string {
	return sanitizeField(s.Field)
}

type Environmental struct {
	ConfidentialityRequirements string
	IntegrityRequirements       string
	AvailabilityRequirements    string
}

func GetEnvironmental(ctx Context) Environmental {
	env := Environmental{
		ConfidentialityRequirements: ctx.QueryParam("confidentialityRequirements"),
		IntegrityRequirements:       ctx.QueryParam("integrityRequirements"),
		AvailabilityRequirements:    ctx.QueryParam("availabilityRequirements"),
	}
	return SanitizeEnv(env)
}

func SanitizeEnv(env Environmental) Environmental {

	replacements := map[string]string{
		"high":   "H",
		"medium": "M",
		"low":    "L",
	}

	replaceValue := func(value string) string {
		if newValue, exists := replacements[value]; exists {
			return newValue
		}
		return value
	}

	env.ConfidentialityRequirements = replaceValue(env.ConfidentialityRequirements)
	env.IntegrityRequirements = replaceValue(env.IntegrityRequirements)
	env.AvailabilityRequirements = replaceValue(env.AvailabilityRequirements)

	return env
}

type BadgeValues struct {
	Key   string
	Value int
	Color string
}

type badgeRect struct {
	X      int
	Width  int
	Height int
	Color  string
}

type badgeText struct {
	X       string
	Content string
}

type badgeSVGData struct {
	TotalWidth int
	BoxHeight  int
	LabelWidth int
	Label      string
	Rects      []badgeRect
	Texts      []badgeText
}

var badgeSVGTmpl = template.Must(template.New("badge").Parse(
	`<svg xmlns="http://www.w3.org/2000/svg" width="{{.TotalWidth}}" height="{{.BoxHeight}}" role="img" aria-label="{{.Label}}">` +
		`<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>` +
		`<clipPath id="r"><rect width="{{.TotalWidth}}" height="{{.BoxHeight}}" rx="3" fill="#fff"/></clipPath>` +
		`<g clip-path="url(#r)">` +
		`<rect width="{{.LabelWidth}}" height="{{.BoxHeight}}" fill="#000"/>` +
		`{{range .Rects}}<rect x="{{.X}}" width="{{.Width}}" height="{{.Height}}" fill="{{.Color}}"/>{{end}}` +
		`<rect width="{{.TotalWidth}}" height="{{.BoxHeight}}" fill="url(#s)"/></g>` +
		`<g fill="#fff" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" text-rendering="geometricPrecision">` +
		`<text x="4" y="14">{{.Label}}</text>` +
		`{{range .Texts}}<text x="{{.X}}" y="14" text-anchor="middle">{{.Content}}</text>{{end}}` +
		`</g></svg>`,
))

func GetBadgeSVG(label string, values []BadgeValues) string {
	labelWidth := 40
	boxHeight := 20

	maxDigits := 1
	for _, val := range values {
		if digits := len(strconv.Itoa(val.Value)); digits > maxDigits {
			maxDigits = digits
		}
	}

	boxWidth := 25
	if maxDigits == 2 {
		boxWidth = 35
	} else if maxDigits >= 3 {
		boxWidth = 45
	}
	if len(values) == 1 {
		boxWidth = 60
	}

	totalWidth := labelWidth + len(values)*boxWidth

	rects := make([]badgeRect, len(values))
	for i, val := range values {
		rects[i] = badgeRect{
			X:      labelWidth + i*boxWidth,
			Width:  boxWidth,
			Height: boxHeight,
			Color:  val.Color,
		}
	}

	texts := make([]badgeText, len(values))
	for i, val := range values {
		x := float64(labelWidth) + float64(i)*float64(boxWidth) + float64(boxWidth)/2.0
		content := val.Key
		if len(values) > 1 {
			content = fmt.Sprintf("%s:%d", val.Key, val.Value)
		}
		texts[i] = badgeText{
			X:       fmt.Sprintf("%.1f", x),
			Content: content,
		}
	}

	var buf bytes.Buffer
	if err := badgeSVGTmpl.Execute(&buf, badgeSVGData{
		TotalWidth: totalWidth,
		BoxHeight:  boxHeight,
		LabelWidth: labelWidth,
		Label:      label,
		Rects:      rects,
		Texts:      texts,
	}); err != nil {
		return ""
	}
	return buf.String()
}

func CreateLinkedCtx(ctx context.Context) context.Context {
	return trace.ContextWithSpan(context.Background(), trace.SpanFromContext(ctx))
}

// CopyContextValues copies every request-scoped value that might still be
// needed once the original request has ended (e.g. inside a spawned goroutine)
// from src into dst. It's the only place outside the accessor functions above
// allowed to know the full set of context keys.
func CopyContextValues(src, dst Context) {
	if i, ok := MaybeGetThirdPartyIntegration(src); ok {
		SetThirdPartyIntegration(dst, i)
	}
	if session, ok := MaybeGetSession(src); ok {
		SetSession(dst, session)
	}
	if org, err := MaybeGetOrganization(src); err == nil {
		SetOrg(dst, org)
	}
	if project, err := MaybeGetProject(src); err == nil {
		SetProject(dst, project)
	}
	if asset, err := MaybeGetAsset(src); err == nil {
		SetAsset(dst, asset)
	}
	if assetVersion, err := MaybeGetAssetVersion(src); err == nil {
		SetAssetVersion(dst, assetVersion)
	}
	if rbac, ok := MaybeGetRBAC(src); ok {
		SetRBAC(dst, rbac)
	}
	if authClient, ok := MaybeGetAuthAdminClient(src); ok {
		SetAuthAdminClient(dst, authClient)
	}
	if orgSlug, err := GetOrgSlug(src); err == nil {
		SetOrgSlug(dst, orgSlug)
	}
	if projectSlug, err := GetProjectSlug(src); err == nil {
		SetProjectSlug(dst, projectSlug)
	}
	if assetSlug, err := GetAssetSlug(src); err == nil {
		SetAssetSlug(dst, assetSlug)
	}
	if IsPublicRequest(src) {
		SetIsPublicRequest(dst)
	}
}
