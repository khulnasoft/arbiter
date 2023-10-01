// Package issues provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.12.4 DO NOT EDIT.
package issues

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	openapi_types "github.com/deepmap/oapi-codegen/pkg/types"
)

const (
	APITokenScopes   = "APIToken.Scopes"
	BearerAuthScopes = "BearerAuth.Scopes"
)

// Defines values for CommonIssueModelAttributesEffectiveSeverityLevel.
const (
	CommonIssueModelAttributesEffectiveSeverityLevelCritical CommonIssueModelAttributesEffectiveSeverityLevel = "critical"
	CommonIssueModelAttributesEffectiveSeverityLevelHigh     CommonIssueModelAttributesEffectiveSeverityLevel = "high"
	CommonIssueModelAttributesEffectiveSeverityLevelInfo     CommonIssueModelAttributesEffectiveSeverityLevel = "info"
	CommonIssueModelAttributesEffectiveSeverityLevelLow      CommonIssueModelAttributesEffectiveSeverityLevel = "low"
	CommonIssueModelAttributesEffectiveSeverityLevelMedium   CommonIssueModelAttributesEffectiveSeverityLevel = "medium"
)

// Defines values for CommonIssueModelVTwoAttributesEffectiveSeverityLevel.
const (
	CommonIssueModelVTwoAttributesEffectiveSeverityLevelCritical CommonIssueModelVTwoAttributesEffectiveSeverityLevel = "critical"
	CommonIssueModelVTwoAttributesEffectiveSeverityLevelHigh     CommonIssueModelVTwoAttributesEffectiveSeverityLevel = "high"
	CommonIssueModelVTwoAttributesEffectiveSeverityLevelInfo     CommonIssueModelVTwoAttributesEffectiveSeverityLevel = "info"
	CommonIssueModelVTwoAttributesEffectiveSeverityLevelLow      CommonIssueModelVTwoAttributesEffectiveSeverityLevel = "low"
	CommonIssueModelVTwoAttributesEffectiveSeverityLevelMedium   CommonIssueModelVTwoAttributesEffectiveSeverityLevel = "medium"
)

// ActualVersion Resolved API version
type ActualVersion = string

// BulkPackageUrlsRequestBody defines model for BulkPackageUrlsRequestBody.
type BulkPackageUrlsRequestBody struct {
	Data struct {
		Attributes struct {
			// Purls An array of Package URLs (purl). Supported purl types are apk, cargo, cocoapods, composer, deb, gem, generic, hex, maven, npm, nuget, pypi, rpm, and swift. A version for the package is also required.
			Purls []string `json:"purls"`
		} `json:"attributes"`
		Type *Types `json:"type,omitempty"`
	} `json:"data"`
}

// CommonIssueModel defines model for CommonIssueModel.
type CommonIssueModel struct {
	Attributes *struct {
		Coordinates *[]Coordinate `json:"coordinates,omitempty"`
		CreatedAt   *time.Time    `json:"created_at,omitempty"`

		// Description A description of the issue in Markdown format
		Description *string `json:"description,omitempty"`

		// EffectiveSeverityLevel The type from enumeration of the issue’s severity level. This is usually set from the issue’s producer, but can be overridden by policies.
		EffectiveSeverityLevel *CommonIssueModelAttributesEffectiveSeverityLevel `json:"effective_severity_level,omitempty"`

		// Key The Khulnasoft vulnerability ID.
		Key      *string    `json:"key,omitempty"`
		Problems *[]Problem `json:"problems,omitempty"`

		// Severities The severity level of the vulnerability: ‘low’, ‘medium’, ‘high’ or ‘critical’.
		Severities *[]Severity `json:"severities,omitempty"`
		Slots      *Slots      `json:"slots,omitempty"`

		// Title A human-readable title for this issue.
		Title *string `json:"title,omitempty"`

		// Type The issue type
		Type *string `json:"type,omitempty"`

		// UpdatedAt When the vulnerability information was last modified.
		UpdatedAt *time.Time `json:"updated_at,omitempty"`
	} `json:"attributes,omitempty"`

	// Id The Khulnasoft ID of the vulnerability.
	Id *string `json:"id,omitempty"`

	// Type The type of the REST resource. Always ‘issue’.
	Type *string `json:"type,omitempty"`
}

// CommonIssueModelAttributesEffectiveSeverityLevel The type from enumeration of the issue’s severity level. This is usually set from the issue’s producer, but can be overridden by policies.
type CommonIssueModelAttributesEffectiveSeverityLevel string

// CommonIssueModelVTwo defines model for CommonIssueModelVTwo.
type CommonIssueModelVTwo struct {
	Attributes *struct {
		Coordinates *[]CoordinateVTwo `json:"coordinates,omitempty"`
		CreatedAt   *time.Time        `json:"created_at,omitempty"`

		// Description A description of the issue in Markdown format
		Description *string `json:"description,omitempty"`

		// EffectiveSeverityLevel The type from enumeration of the issue’s severity level. This is usually set from the issue’s producer, but can be overridden by policies.
		EffectiveSeverityLevel *CommonIssueModelVTwoAttributesEffectiveSeverityLevel `json:"effective_severity_level,omitempty"`
		Problems               *[]Problem                                            `json:"problems,omitempty"`

		// Severities The severity level of the vulnerability: ‘low’, ‘medium’, ‘high’ or ‘critical’.
		Severities *[]Severity `json:"severities,omitempty"`
		Slots      *Slots      `json:"slots,omitempty"`

		// Title A human-readable title for this issue.
		Title *string `json:"title,omitempty"`

		// Type The issue type
		Type *string `json:"type,omitempty"`

		// UpdatedAt When the vulnerability information was last modified.
		UpdatedAt *time.Time `json:"updated_at,omitempty"`
	} `json:"attributes,omitempty"`

	// Id The Khulnasoft ID of the vulnerability.
	Id *string `json:"id,omitempty"`

	// Type The type of the REST resource. Always ‘issue’.
	Type *string `json:"type,omitempty"`
}

// CommonIssueModelVTwoAttributesEffectiveSeverityLevel The type from enumeration of the issue’s severity level. This is usually set from the issue’s producer, but can be overridden by policies.
type CommonIssueModelVTwoAttributesEffectiveSeverityLevel string

// Coordinate defines model for Coordinate.
type Coordinate struct {
	Remedies *[]Remedy `json:"remedies,omitempty"`

	// Representation The affected versions of this vulnerability.
	Representation *[]string `json:"representation,omitempty"`
}

// CoordinateVTwo defines model for CoordinateVTwo.
type CoordinateVTwo struct {
	Remedies *[]Remedy `json:"remedies,omitempty"`

	// Representations The affected versions of this vulnerability.
	Representations []CoordinateVTwo_Representations_Item `json:"representations"`
}

// CoordinateVTwo_Representations_Item defines model for CoordinateVTwo.representations.Item.
type CoordinateVTwo_Representations_Item struct {
	union json.RawMessage
}

// Error defines model for Error.
type Error struct {
	// Code An application-specific error code, expressed as a string value.
	Code *string `json:"code,omitempty"`

	// Detail A human-readable explanation specific to this occurrence of the problem.
	Detail string `json:"detail"`

	// Id A unique identifier for this particular occurrence of the problem.
	Id *openapi_types.UUID `json:"id,omitempty"`

	// Links A link that leads to further details about this particular occurrance of the problem.
	Links  *ErrorLink              `json:"links,omitempty"`
	Meta   *map[string]interface{} `json:"meta,omitempty"`
	Source *struct {
		// Parameter A string indicating which URI query parameter caused the error.
		Parameter *string `json:"parameter,omitempty"`

		// Pointer A JSON Pointer [RFC6901] to the associated entity in the request document.
		Pointer *string `json:"pointer,omitempty"`
	} `json:"source,omitempty"`

	// Status The HTTP status code applicable to this problem, expressed as a string value.
	Status string `json:"status"`

	// Title A short, human-readable summary of the problem that SHOULD NOT change from occurrence to occurrence of the problem, except for purposes of localization.
	Title *string `json:"title,omitempty"`
}

// ErrorDocument defines model for ErrorDocument.
type ErrorDocument struct {
	Errors  []Error `json:"errors"`
	Jsonapi JsonApi `json:"jsonapi"`
}

// ErrorLink A link that leads to further details about this particular occurrance of the problem.
type ErrorLink struct {
	About *LinkProperty `json:"about,omitempty"`
}

// IssuesMeta defines model for IssuesMeta.
type IssuesMeta struct {
	Package *PackageMeta `json:"package,omitempty"`
}

// IssuesResponse defines model for IssuesResponse.
type IssuesResponse struct {
	Data    *[]CommonIssueModel `json:"data,omitempty"`
	Jsonapi *JsonApi            `json:"jsonapi,omitempty"`
	Links   *PaginatedLinks     `json:"links,omitempty"`
	Meta    *IssuesMeta         `json:"meta,omitempty"`
}

// IssuesWithPurlsResponse defines model for IssuesWithPurlsResponse.
type IssuesWithPurlsResponse struct {
	Data    *[]CommonIssueModelVTwo `json:"data,omitempty"`
	Jsonapi *JsonApi                `json:"jsonapi,omitempty"`
	Links   *PaginatedLinks         `json:"links,omitempty"`
}

// JsonApi defines model for JsonApi.
type JsonApi struct {
	// Version Version of the JSON API specification this server supports.
	Version string `json:"version"`
}

// LinkProperty defines model for LinkProperty.
type LinkProperty struct {
	union json.RawMessage
}

// LinkProperty0 A string containing the link’s URL.
type LinkProperty0 = string

// LinkProperty1 defines model for .
type LinkProperty1 struct {
	// Href A string containing the link’s URL.
	Href string `json:"href"`

	// Meta Free-form object that may contain non-standard information.
	Meta *Meta `json:"meta,omitempty"`
}

// Meta Free-form object that may contain non-standard information.
type Meta map[string]interface{}

// PackageMeta defines model for PackageMeta.
type PackageMeta struct {
	// Name The package’s name
	Name *string `json:"name,omitempty"`

	// Namespace A name prefix, such as a maven group id or docker image owner
	Namespace *string `json:"namespace,omitempty"`

	// Type The package type or protocol
	Type *string `json:"type,omitempty"`

	// Url The purl of the package
	Url *string `json:"url,omitempty"`

	// Version The version of the package
	Version *string `json:"version,omitempty"`
}

// PackageRepresentation defines model for PackageRepresentation.
type PackageRepresentation struct {
	Package *PackageMeta `json:"package,omitempty"`
}

// PaginatedLinks defines model for PaginatedLinks.
type PaginatedLinks struct {
	First *LinkProperty `json:"first,omitempty"`
	Last  *LinkProperty `json:"last,omitempty"`
	Next  *LinkProperty `json:"next,omitempty"`
	Prev  *LinkProperty `json:"prev,omitempty"`
	Self  *LinkProperty `json:"self,omitempty"`
}

// Problem defines model for Problem.
type Problem struct {
	// DisclosedAt When this problem was disclosed to the public.
	DisclosedAt *time.Time `json:"disclosed_at,omitempty"`

	// DiscoveredAt When this problem was first discovered.
	DiscoveredAt *time.Time `json:"discovered_at,omitempty"`
	Id           string     `json:"id"`
	Source       string     `json:"source"`

	// UpdatedAt When this problem was last updated.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`

	// Url An optional URL for this problem.
	Url *string `json:"url,omitempty"`
}

// QueryVersion Requested API version
type QueryVersion = string

// Remedy defines model for Remedy.
type Remedy struct {
	// Description A markdown-formatted optional description of this remedy.
	Description *string `json:"description,omitempty"`
	Details     *struct {
		// UpgradePackage A minimum version to upgrade to in order to remedy the issue.
		UpgradePackage *string `json:"upgrade_package,omitempty"`
	} `json:"details,omitempty"`

	// Type The type of the remedy. Always ‘indeterminate’.
	Type *string `json:"type,omitempty"`
}

// ResourcePath defines model for ResourcePath.
type ResourcePath = string

// ResourcePathRepresentation An object that contains an opaque identifying string.
type ResourcePathRepresentation struct {
	ResourcePath ResourcePath `json:"resource_path"`
}

// Severity defines model for Severity.
type Severity struct {
	Level *string `json:"level,omitempty"`

	// Score The CVSSv3 value of the vulnerability.
	Score *float32 `json:"score"`

	// Source The source of this severity. The value must be the id of a referenced problem or class, in which case that problem or class is the source of this issue. If source is omitted, this severity is sourced internally in the Khulnasoft application.
	Source *string `json:"source,omitempty"`

	// Vector The CVSSv3 value of the vulnerability.
	Vector *string `json:"vector"`
}

// Slots defines model for Slots.
type Slots struct {
	// DisclosureTime The time at which this vulnerability was disclosed.
	DisclosureTime *time.Time `json:"disclosure_time,omitempty"`

	// Exploit The exploit maturity. Value of ‘No Data’, ‘Not Defined’, ‘Unproven’, ‘Proof of Concept’, ‘Functional’ or ‘High’.
	Exploit *string `json:"exploit,omitempty"`

	// PublicationTime The time at which this vulnerability was published.
	PublicationTime *string `json:"publication_time,omitempty"`
	References      *[]struct {
		// Title Descriptor for an external reference to the issue
		Title *string `json:"title,omitempty"`

		// Url URL for an external reference to the issue
		Url *string `json:"url,omitempty"`
	} `json:"references,omitempty"`
}

// Types defines model for Types.
type Types = string

// OrgId defines model for OrgId.
type OrgId = openapi_types.UUID

// PackageUrl defines model for PackageUrl.
type PackageUrl = string

// Version Requested API version
type Version = QueryVersion

// ListIssuesForManyPurlsParams defines parameters for ListIssuesForManyPurls.
type ListIssuesForManyPurlsParams struct {
	// Version The requested version of the endpoint to process the request
	Version Version `form:"version" json:"version"`
}

// FetchIssuesPerPurlParams defines parameters for FetchIssuesPerPurl.
type FetchIssuesPerPurlParams struct {
	// Version The requested version of the endpoint to process the request
	Version Version `form:"version" json:"version"`

	// Offset Specify the number of results to skip before returning results. Must be greater than or equal to 0. Default is 0.
	Offset *float32 `form:"offset,omitempty" json:"offset,omitempty"`

	// Limit Specify the number of results to return. Must be greater than 0 and less than 1000. Default is 1000.
	Limit *float32 `form:"limit,omitempty" json:"limit,omitempty"`
}

// ListIssuesForManyPurlsJSONRequestBody defines body for ListIssuesForManyPurls for application/vnd.api+json ContentType.
type ListIssuesForManyPurlsJSONRequestBody = BulkPackageUrlsRequestBody

// AsResourcePathRepresentation returns the union data inside the CoordinateVTwo_Representations_Item as a ResourcePathRepresentation
func (t CoordinateVTwo_Representations_Item) AsResourcePathRepresentation() (ResourcePathRepresentation, error) {
	var body ResourcePathRepresentation
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromResourcePathRepresentation overwrites any union data inside the CoordinateVTwo_Representations_Item as the provided ResourcePathRepresentation
func (t *CoordinateVTwo_Representations_Item) FromResourcePathRepresentation(v ResourcePathRepresentation) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergeResourcePathRepresentation performs a merge with any union data inside the CoordinateVTwo_Representations_Item, using the provided ResourcePathRepresentation
func (t *CoordinateVTwo_Representations_Item) MergeResourcePathRepresentation(v ResourcePathRepresentation) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(b, t.union)
	t.union = merged
	return err
}

// AsPackageRepresentation returns the union data inside the CoordinateVTwo_Representations_Item as a PackageRepresentation
func (t CoordinateVTwo_Representations_Item) AsPackageRepresentation() (PackageRepresentation, error) {
	var body PackageRepresentation
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromPackageRepresentation overwrites any union data inside the CoordinateVTwo_Representations_Item as the provided PackageRepresentation
func (t *CoordinateVTwo_Representations_Item) FromPackageRepresentation(v PackageRepresentation) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergePackageRepresentation performs a merge with any union data inside the CoordinateVTwo_Representations_Item, using the provided PackageRepresentation
func (t *CoordinateVTwo_Representations_Item) MergePackageRepresentation(v PackageRepresentation) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(b, t.union)
	t.union = merged
	return err
}

func (t CoordinateVTwo_Representations_Item) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	return b, err
}

func (t *CoordinateVTwo_Representations_Item) UnmarshalJSON(b []byte) error {
	err := t.union.UnmarshalJSON(b)
	return err
}

// AsLinkProperty0 returns the union data inside the LinkProperty as a LinkProperty0
func (t LinkProperty) AsLinkProperty0() (LinkProperty0, error) {
	var body LinkProperty0
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromLinkProperty0 overwrites any union data inside the LinkProperty as the provided LinkProperty0
func (t *LinkProperty) FromLinkProperty0(v LinkProperty0) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergeLinkProperty0 performs a merge with any union data inside the LinkProperty, using the provided LinkProperty0
func (t *LinkProperty) MergeLinkProperty0(v LinkProperty0) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(b, t.union)
	t.union = merged
	return err
}

// AsLinkProperty1 returns the union data inside the LinkProperty as a LinkProperty1
func (t LinkProperty) AsLinkProperty1() (LinkProperty1, error) {
	var body LinkProperty1
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromLinkProperty1 overwrites any union data inside the LinkProperty as the provided LinkProperty1
func (t *LinkProperty) FromLinkProperty1(v LinkProperty1) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergeLinkProperty1 performs a merge with any union data inside the LinkProperty, using the provided LinkProperty1
func (t *LinkProperty) MergeLinkProperty1(v LinkProperty1) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(b, t.union)
	t.union = merged
	return err
}

func (t LinkProperty) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	return b, err
}

func (t *LinkProperty) UnmarshalJSON(b []byte) error {
	err := t.union.UnmarshalJSON(b)
	return err
}

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// ListIssuesForManyPurls request with any body
	ListIssuesForManyPurlsWithBody(ctx context.Context, orgId OrgId, params *ListIssuesForManyPurlsParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	ListIssuesForManyPurls(ctx context.Context, orgId OrgId, params *ListIssuesForManyPurlsParams, body ListIssuesForManyPurlsJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// FetchIssuesPerPurl request
	FetchIssuesPerPurl(ctx context.Context, orgId OrgId, purl PackageUrl, params *FetchIssuesPerPurlParams, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) ListIssuesForManyPurlsWithBody(ctx context.Context, orgId OrgId, params *ListIssuesForManyPurlsParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewListIssuesForManyPurlsRequestWithBody(c.Server, orgId, params, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) ListIssuesForManyPurls(ctx context.Context, orgId OrgId, params *ListIssuesForManyPurlsParams, body ListIssuesForManyPurlsJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewListIssuesForManyPurlsRequest(c.Server, orgId, params, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) FetchIssuesPerPurl(ctx context.Context, orgId OrgId, purl PackageUrl, params *FetchIssuesPerPurlParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewFetchIssuesPerPurlRequest(c.Server, orgId, purl, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewListIssuesForManyPurlsRequest calls the generic ListIssuesForManyPurls builder with application/vnd.api+json body
func NewListIssuesForManyPurlsRequest(server string, orgId OrgId, params *ListIssuesForManyPurlsParams, body ListIssuesForManyPurlsJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewListIssuesForManyPurlsRequestWithBody(server, orgId, params, "application/vnd.api+json", bodyReader)
}

// NewListIssuesForManyPurlsRequestWithBody generates requests for ListIssuesForManyPurls with any type of body
func NewListIssuesForManyPurlsRequestWithBody(server string, orgId OrgId, params *ListIssuesForManyPurlsParams, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "org_id", runtime.ParamLocationPath, orgId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/orgs/%s/packages/issues", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	queryValues := queryURL.Query()

	if queryFrag, err := runtime.StyleParamWithLocation("form", true, "version", runtime.ParamLocationQuery, params.Version); err != nil {
		return nil, err
	} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
		return nil, err
	} else {
		for k, v := range parsed {
			for _, v2 := range v {
				queryValues.Add(k, v2)
			}
		}
	}

	queryURL.RawQuery = queryValues.Encode()

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewFetchIssuesPerPurlRequest generates requests for FetchIssuesPerPurl
func NewFetchIssuesPerPurlRequest(server string, orgId OrgId, purl PackageUrl, params *FetchIssuesPerPurlParams) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "org_id", runtime.ParamLocationPath, orgId)
	if err != nil {
		return nil, err
	}

	var pathParam1 string

	pathParam1, err = runtime.StyleParamWithLocation("simple", false, "purl", runtime.ParamLocationQuery, purl)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/orgs/%s/packages/%s/issues", pathParam0, pathParam1)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	queryValues := queryURL.Query()

	if queryFrag, err := runtime.StyleParamWithLocation("form", true, "version", runtime.ParamLocationQuery, params.Version); err != nil {
		return nil, err
	} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
		return nil, err
	} else {
		for k, v := range parsed {
			for _, v2 := range v {
				queryValues.Add(k, v2)
			}
		}
	}

	if params.Offset != nil {

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "offset", runtime.ParamLocationQuery, *params.Offset); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

	}

	if params.Limit != nil {

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "limit", runtime.ParamLocationQuery, *params.Limit); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

	}

	queryURL.RawQuery = queryValues.Encode()

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// ListIssuesForManyPurls request with any body
	ListIssuesForManyPurlsWithBodyWithResponse(ctx context.Context, orgId OrgId, params *ListIssuesForManyPurlsParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*ListIssuesForManyPurlsResponse, error)

	ListIssuesForManyPurlsWithResponse(ctx context.Context, orgId OrgId, params *ListIssuesForManyPurlsParams, body ListIssuesForManyPurlsJSONRequestBody, reqEditors ...RequestEditorFn) (*ListIssuesForManyPurlsResponse, error)

	// FetchIssuesPerPurl request
	FetchIssuesPerPurlWithResponse(ctx context.Context, orgId OrgId, purl PackageUrl, params *FetchIssuesPerPurlParams, reqEditors ...RequestEditorFn) (*FetchIssuesPerPurlResponse, error)
}

type ListIssuesForManyPurlsResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r ListIssuesForManyPurlsResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ListIssuesForManyPurlsResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type FetchIssuesPerPurlResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r FetchIssuesPerPurlResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r FetchIssuesPerPurlResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// ListIssuesForManyPurlsWithBodyWithResponse request with arbitrary body returning *ListIssuesForManyPurlsResponse
func (c *ClientWithResponses) ListIssuesForManyPurlsWithBodyWithResponse(ctx context.Context, orgId OrgId, params *ListIssuesForManyPurlsParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*ListIssuesForManyPurlsResponse, error) {
	rsp, err := c.ListIssuesForManyPurlsWithBody(ctx, orgId, params, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseListIssuesForManyPurlsResponse(rsp)
}

func (c *ClientWithResponses) ListIssuesForManyPurlsWithResponse(ctx context.Context, orgId OrgId, params *ListIssuesForManyPurlsParams, body ListIssuesForManyPurlsJSONRequestBody, reqEditors ...RequestEditorFn) (*ListIssuesForManyPurlsResponse, error) {
	rsp, err := c.ListIssuesForManyPurls(ctx, orgId, params, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseListIssuesForManyPurlsResponse(rsp)
}

// FetchIssuesPerPurlWithResponse request returning *FetchIssuesPerPurlResponse
func (c *ClientWithResponses) FetchIssuesPerPurlWithResponse(ctx context.Context, orgId OrgId, purl PackageUrl, params *FetchIssuesPerPurlParams, reqEditors ...RequestEditorFn) (*FetchIssuesPerPurlResponse, error) {
	rsp, err := c.FetchIssuesPerPurl(ctx, orgId, purl, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseFetchIssuesPerPurlResponse(rsp)
}

// ParseListIssuesForManyPurlsResponse parses an HTTP response from a ListIssuesForManyPurlsWithResponse call
func ParseListIssuesForManyPurlsResponse(rsp *http.Response) (*ListIssuesForManyPurlsResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &ListIssuesForManyPurlsResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseFetchIssuesPerPurlResponse parses an HTTP response from a FetchIssuesPerPurlWithResponse call
func ParseFetchIssuesPerPurlResponse(rsp *http.Response) (*FetchIssuesPerPurlResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &FetchIssuesPerPurlResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}
