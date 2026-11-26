// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package protostruct supports operations on the protocol buffer Struct message.
package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	libAuth "github.com/apigee/apigee-remote-service-golib/v2/auth"
	apigeeContext "github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/apigee/apigee-remote-service-golib/v2/quota"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRegister(t *testing.T) {
	opts := []grpc.ServerOption{}
	grpcServer := grpc.NewServer(opts...)
	server := AuthorizationServer{}
	h := &Handler{}
	server.Register(grpcServer, h)
	if h != server.handler {
		t.Errorf("want: %v, got: %v", h, server.handler)
	}
	grpcServer.Stop()
}

func TestCheck(t *testing.T) {

	jwtClaims := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"apigee": {
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"api_product_list": {
								Kind: &structpb.Value_StringValue{
									StringValue: "product1,product2",
								},
							},
						},
					},
				},
			},
		},
	}

	headers := map[string]string{}

	products := product.ProductsNameMap{
		"product1": &product.APIProduct{
			DisplayName: "product1",
		},
	}

	uri := "path?x-api-key=foo"
	req := &v3.CheckRequest{
		Attributes: &v3.AttributeContext{
			Request: &v3.AttributeContext_Request{
				Http: &v3.AttributeContext_HttpRequest{
					Path:    uri,
					Headers: headers,
				},
			},
			MetadataContext: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					jwtFilterMetadataKey: jwtClaims,
				},
			},
		},
	}

	testAuthMan := &testAuthMan{}
	testProductMan := &testProductMan{
		api:     "api",
		resolve: true,
	}
	testQuotaMan := &testQuotaMan{}
	testAnalyticsMan := &testAnalyticsMan{}
	server := AuthorizationServer{
		handler: &Handler{
			apiKeyClaim:           headerClientID,
			apiHeader:             headerAPI,
			apiKeyHeader:          "x-api-key",
			authMan:               testAuthMan,
			productMan:            testProductMan,
			quotaMan:              testQuotaMan,
			jwtProviderKey:        "apigee",
			appendMetadataHeaders: true,
			analyticsMan:          testAnalyticsMan,
		},
	}

	// no api header
	var resp *v3.CheckResponse
	var err error
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.UNAUTHENTICATED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.UNAUTHENTICATED))
	}
	headers[headerAPI] = "api"

	// ErrNoAuth
	testAuthMan.sendAuth(nil, libAuth.ErrNoAuth)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.UNAUTHENTICATED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.UNAUTHENTICATED))
	}

	// ErrBadAuth
	testAuthMan.sendAuth(nil, libAuth.ErrBadAuth)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// ErrInternalError
	testAuthMan.sendAuth(nil, libAuth.ErrInternalError)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.INTERNAL) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.INTERNAL))
	}

	// reset auth error
	testAuthMan.sendAuth(nil, nil)

	// no products
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// no matched products
	testAuthMan.sendAuth(&libAuth.Context{
		APIProducts: []string{"no match"},
	}, nil)
	testProductMan.products = products
	testProductMan.resolve = false
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}
	testProductMan.resolve = true

	// no products authenticated
	testAuthMan.sendAuth(&libAuth.Context{
		APIProducts: []string{},
	}, nil)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// valid auth
	testAuthMan.sendAuth(&libAuth.Context{
		APIProducts: []string{"product1"},
	}, nil)

	// quota exceeded
	products["product1"].QuotaLimitInt = 2
	testQuotaMan.exceeded = 2
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.RESOURCE_EXHAUSTED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.RESOURCE_EXHAUSTED))
	}
	code := resp.HttpResponse.(*v3.CheckResponse_DeniedResponse).DeniedResponse.Status.Code
	if code != http.StatusTooManyRequests {
		t.Errorf("got: %d, want: %d", code, http.StatusTooManyRequests)
	}
	testQuotaMan.exceeded = 0

	// quota error
	testQuotaMan.sendError = errors.New("quota error")
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.INTERNAL) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.INTERNAL))
	}
	testQuotaMan.sendError = nil

	// all OK
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}

	// bad api in context metadata
	req.Attributes.ContextExtensions = map[string]string{}
	req.Attributes.ContextExtensions[apiContextKey] = "bad-api"
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	// good api in context supersedes even if api header is bad
	headers[headerAPI] = "bad-api"
	req.Attributes.ContextExtensions[apiContextKey] = "api"
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}
	delete(req.Attributes.ContextExtensions, apiContextKey)
	headers[headerAPI] = "api"

	// testAuthMan.ctx
	if testAuthMan.apiKey != "foo" {
		t.Errorf("got: %s, want: %s", testAuthMan.apiKey, "foo")
	}
	// testAuthMan.claims
	if testAuthMan.apiKeyClaimKey != headerClientID {
		t.Errorf("got: %s, want: %s", testAuthMan.apiKeyClaimKey, headerClientID)
	}

	// non-existing jwtProviderKey
	server.handler.jwtProviderKey = "not-apigee"
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}

	// testAuthMan.claims should be nil
	if len(testAuthMan.claims) != 0 {
		t.Errorf("got: %d, want: empty claims", len(testAuthMan.claims))
	}

	// empty jwtProviderKey should not adopt raw api_product_list claims
	server.handler.jwtProviderKey = ""
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}

	// testAuthMan.claims should be nil when jwtProviderKey is unset and no apiKeyClaim is present
	if len(testAuthMan.claims) != 0 {
		t.Errorf("got: %d, want: empty claims", len(testAuthMan.claims))
	}

	// check deny when allowUnauthorized = true
	server.handler.allowUnauthorized = true
	testProductMan.resolve = false
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}

	// improper context, not multitenant
	server.handler.envName = "test"
	req.Attributes.ContextExtensions[envContextKey] = "prod"
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.INTERNAL) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.INTERNAL))
	}

	// multitenant missing context
	server.handler.envName = "*"
	server.handler.isMultitenant = true
	delete(req.Attributes.ContextExtensions, envContextKey)
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.INTERNAL) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.INTERNAL))
	}

	// multitenant receives context
	req.Attributes.ContextExtensions[envContextKey] = "test"
	if resp, err = server.Check(context.Background(), req); err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.OK) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.OK))
	}
}

func TestImmediateAnalytics(t *testing.T) {

	jwtClaims := &structpb.Struct{}

	headers := map[string]string{
		"User-Agent":      "User-Agent",
		"X-Forwarded-For": "X-Forwarded-For",
		headerAPI:         "api",
	}

	requestPath := "path"
	uri := requestPath + "?x-api-key=foo"
	requestTime := time.Now()
	nowProto := timestamppb.New(requestTime)

	req := &v3.CheckRequest{
		Attributes: &v3.AttributeContext{
			Request: &v3.AttributeContext_Request{
				Http: &v3.AttributeContext_HttpRequest{
					Path:    uri,
					Headers: headers,
					Method:  http.MethodGet,
				},
				Time: nowProto,
			},
			MetadataContext: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					jwtFilterMetadataKey: jwtClaims,
				},
			},
		},
	}

	testAuthMan := &testAuthMan{}
	ac := &libAuth.Context{
		ClientID:         "client id",
		AccessToken:      "token",
		Application:      "app",
		APIProducts:      []string{"not-accepted-product", "accepted-product"},
		Expires:          time.Now(),
		DeveloperEmail:   "email",
		Scopes:           []string{"scope"},
		APIKey:           "apikey",
		CustomAttributes: "{\"tier\":\"standard\"}",
		AnalyticsProduct: "accepted-product",
	}
	testAuthMan.sendAuth(ac, libAuth.ErrBadAuth)

	testProductMan := &testProductMan{
		resolve: true,
		api:     "api",
	}
	testQuotaMan := &testQuotaMan{}
	testAnalyticsMan := &testAnalyticsMan{}
	server := AuthorizationServer{
		handler: &Handler{
			orgName:               "org",
			envName:               "env",
			apiKeyClaim:           headerClientID,
			apiHeader:             headerAPI,
			apiKeyHeader:          "x-api-key",
			authMan:               testAuthMan,
			productMan:            testProductMan,
			quotaMan:              testQuotaMan,
			analyticsMan:          testAnalyticsMan,
			jwtProviderKey:        "apigee",
			appendMetadataHeaders: true,
		},
	}

	var resp *v3.CheckResponse
	resp, err := server.Check(context.Background(), req)
	if err != nil {
		t.Errorf("should not get error. got: %s", err)
	}
	if resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Errorf("got: %d, want: %d", resp.Status.Code, int32(rpc.PERMISSION_DENIED))
	}

	if len(testAnalyticsMan.records) != 1 {
		t.Fatalf("got: %d, want: %d", len(testAnalyticsMan.records), 1)
	}

	got := testAnalyticsMan.records[0]
	want := analytics.Record{
		ClientReceivedStartTimestamp: requestTime.UnixNano() / 1000000,
		ClientReceivedEndTimestamp:   requestTime.UnixNano() / 1000000,
		TargetSentStartTimestamp:     0,
		TargetSentEndTimestamp:       0,
		TargetReceivedStartTimestamp: 0,
		TargetReceivedEndTimestamp:   0,
		RecordType:                   "APIAnalytics",
		APIProxy:                     headers[headerAPI],
		RequestURI:                   uri,
		RequestPath:                  requestPath,
		RequestVerb:                  http.MethodGet,
		ClientIP:                     headers["X-Forwarded-For"],
		UserAgent:                    headers["User-Agent"],
		APIProxyRevision:             0,
		ResponseStatusCode:           http.StatusForbidden,
		DeveloperEmail:               ac.DeveloperEmail,
		DeveloperApp:                 ac.Application,
		AccessToken:                  ac.AccessToken,
		ClientID:                     ac.ClientID,
		APIProduct:                   ac.AnalyticsProduct,
		Organization:                 server.handler.orgName,
		Environment:                  server.handler.envName,
		GatewaySource:                gatewaySource,
		// the following fields vary, ignore them
		ClientSentStartTimestamp: got.ClientSentStartTimestamp,
		ClientSentEndTimestamp:   got.ClientSentEndTimestamp,
		GatewayFlowID:            got.GatewayFlowID,
	}

	if got.ClientSentStartTimestamp < requestTime.Unix() {
		t.Errorf("got: %d, want >=: %d", got.ClientSentStartTimestamp, requestTime.Unix())
	}
	if got.ClientSentEndTimestamp < got.ClientSentStartTimestamp {
		t.Errorf("got: %d, want >=: %d", got.ClientSentEndTimestamp, got.ClientSentStartTimestamp)
	}
	if got.GatewayFlowID == "" {
		t.Errorf("GatewayFlowID should not be empty")
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got: %#v, want: %#v", got, want)
	}
}

type testAuthMan struct {
	ctx             apigeeContext.Context
	apiKey          string
	claims          map[string]interface{}
	apiKeyClaimKey  string
	makeContextFunc func(ctx apigeeContext.Context) (*libAuth.Context, error)
}

func (a *testAuthMan) Close() {}
func (a *testAuthMan) Authenticate(ctx apigeeContext.Context, apiKey string, claims map[string]interface{},
	apiKeyClaimKey string) (*libAuth.Context, error) {
	a.ctx = ctx
	a.apiKey = apiKey
	a.claims = claims
	a.apiKeyClaimKey = apiKeyClaimKey

	return a.makeContextFunc(ctx)
}

func (a *testAuthMan) sendAuth(ac *libAuth.Context, err error) {
	if ac == nil {
		ac = &libAuth.Context{}
	}
	a.makeContextFunc = func(ctx apigeeContext.Context) (*libAuth.Context, error) {
		ac.Context = ctx
		return ac, err
	}
}

type testProductMan struct {
	products map[string]*product.APIProduct
	api      string
	resolve  bool
}

func (p *testProductMan) Close() {}
func (p *testProductMan) Products() product.ProductsNameMap {
	return p.products
}
func (p *testProductMan) Authorize(ac *libAuth.Context, api, path, method string) []product.AuthorizedOperation {
	if !p.resolve {
		return nil
	}
	if api != p.api {
		return nil
	}
	values := []product.AuthorizedOperation{}
	for _, p := range p.products {
		values = append(values, product.AuthorizedOperation{
			ID:         p.DisplayName,
			QuotaLimit: 42,
		})
	}
	return values
}

type testQuotaMan struct {
	exceeded  int64
	sendError error
}

func (q *testQuotaMan) Start() {}
func (q *testQuotaMan) Close() {}
func (q *testQuotaMan) Apply(auth *libAuth.Context, p product.AuthorizedOperation, args quota.Args) (*quota.Result, error) {
	if q.sendError != nil {
		return nil, q.sendError
	}
	return &quota.Result{
		Exceeded: q.exceeded,
	}, nil
}

func mustStruct(t *testing.T, m map[string]interface{}) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}
	return s
}

func TestExtractJWTClaims(t *testing.T) {
	t.Run("provider key set adopts only configured provider", func(t *testing.T) {
		meta := mustStruct(t, map[string]interface{}{
			"apigee": map[string]interface{}{
				"api_product_list": []interface{}{"legit-product"},
				"client_id":        "legit-client",
				"application_name": "legit-app",
			},
			"secondary": map[string]interface{}{
				"api_product_list": []interface{}{"attacker-product"},
				"client_id":        "attacker-client",
				"application_name": "attacker-app",
			},
		})
		for i := 0; i < 50; i++ {
			got := extractJWTClaims(meta.GetFields(), "apigee", "client_id")
			if got["client_id"] != "legit-client" {
				t.Fatalf("iter %d: got client_id=%v, want legit-client", i, got["client_id"])
			}
		}
	})

	t.Run("provider key unset ignores raw api_product_list claims", func(t *testing.T) {
		meta := mustStruct(t, map[string]interface{}{
			"secondary": map[string]interface{}{
				"api_product_list": []interface{}{"attacker-product"},
				"application_name": "attacker-app",
			},
		})
		got := extractJWTClaims(meta.GetFields(), "", "client_id")
		if got != nil {
			t.Fatalf("expected nil claims, got %#v", got)
		}
	})

	t.Run("provider key unset forwards only apiKeyClaim string", func(t *testing.T) {
		meta := mustStruct(t, map[string]interface{}{
			"secondary": map[string]interface{}{
				"api_product_list": []interface{}{"attacker-product"},
				"client_id":        "some-key",
				"application_name": "attacker-app",
			},
		})
		got := extractJWTClaims(meta.GetFields(), "", "client_id")
		want := map[string]interface{}{"client_id": "some-key"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})

	t.Run("provider key unset ignores numeric empty and list apiKeyClaim", func(t *testing.T) {
		cases := []map[string]interface{}{
			{"p": map[string]interface{}{"client_id": float64(12345), "api_product_list": []interface{}{"p1"}}},
			{"p": map[string]interface{}{"client_id": "", "api_product_list": []interface{}{"p1"}}},
			{"p": map[string]interface{}{"client_id": []interface{}{"k1", "k2"}, "api_product_list": []interface{}{"p1"}}},
		}
		for i, c := range cases {
			got := extractJWTClaims(mustStruct(t, c).GetFields(), "", "client_id")
			if got != nil {
				t.Errorf("case %d: got %#v, want nil", i, got)
			}
		}
	})

	t.Run("provider key unset ignores conflicting apiKeyClaim across providers", func(t *testing.T) {
		meta := mustStruct(t, map[string]interface{}{
			"apigee": map[string]interface{}{
				"client_id":        "key-a",
				"api_product_list": []interface{}{"p1"},
			},
			"secondary": map[string]interface{}{
				"client_id":        "key-b",
				"api_product_list": []interface{}{"p2"},
			},
		})
		for i := 0; i < 50; i++ {
			got := extractJWTClaims(meta.GetFields(), "", "client_id")
			if got != nil {
				t.Fatalf("iter %d: expected nil on conflicting apiKeyClaim, got %#v", i, got)
			}
		}
	})

	t.Run("provider key unset allows identical apiKeyClaim across providers", func(t *testing.T) {
		meta := mustStruct(t, map[string]interface{}{
			"p1": map[string]interface{}{"client_id": "same-key"},
			"p2": map[string]interface{}{"client_id": "same-key"},
		})
		got := extractJWTClaims(meta.GetFields(), "", "client_id")
		want := map[string]interface{}{"client_id": "same-key"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})
}

func TestCheckJWTProviderConfusionWithRealAuthManager(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwkKey, err := jwk.New(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("jwk.New: %v", err)
	}
	_ = jwkKey.Set(jwk.KeyIDKey, "test-kid")
	_ = jwkKey.Set(jwk.AlgorithmKey, jwa.RS256)
	jwksJSON, err := json.Marshal(map[string]interface{}{"keys": []interface{}{jwkKey}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	makeSignedToken := func(clientID string, products []string) string {
		tok := jwt.New()
		_ = tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
		_ = tok.Set("client_id", clientID)
		_ = tok.Set("application_name", "verified-app")
		_ = tok.Set("api_product_list", products)
		hdrs := jws.NewHeaders()
		_ = hdrs.Set(jws.KeyIDKey, "test-kid")
		signed, err := jwt.Sign(tok, jwa.RS256, privKey, jwt.WithHeaders(hdrs))
		if err != nil {
			t.Fatalf("jwt.Sign: %v", err)
		}
		return string(signed)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/certs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksJSON)
		case "/verifyApiKey":
			var body struct {
				APIKey string `json:"apiKey"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.APIKey == "valid-key" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"token": makeSignedToken("valid-key", []string{"product1"}),
				})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	remoteURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	authMan, err := libAuth.NewManager(libAuth.Options{
		Client: ts.Client(),
		Org:    "org",
	})
	if err != nil {
		t.Fatalf("auth.NewManager: %v", err)
	}
	defer authMan.Close()

	products := product.ProductsNameMap{
		"product1": &product.APIProduct{DisplayName: "product1", Name: "product1"},
	}

	newServer := func(jwtProviderKey string) *AuthorizationServer {
		return &AuthorizationServer{
			handler: &Handler{
				orgName:          "org",
				envName:          "env",
				remoteServiceAPI: remoteURL,
				apiKeyClaim:      "client_id",
				apiHeader:        headerAPI,
				apiKeyHeader:     "x-api-key",
				jwtProviderKey:   jwtProviderKey,
				authMan:          authMan,
				productMan:       &testProductMan{api: "api", resolve: true, products: products},
				quotaMan:         &testQuotaMan{},
				analyticsMan:     &testAnalyticsMan{},
			},
		}
	}

	makeReq := func(path string, headers map[string]string, jwtMeta map[string]interface{}) *v3.CheckRequest {
		if headers == nil {
			headers = map[string]string{}
		}
		headers[headerAPI] = "api"
		var filterMeta map[string]*structpb.Struct
		if jwtMeta != nil {
			filterMeta = map[string]*structpb.Struct{
				jwtFilterMetadataKey: mustStruct(t, jwtMeta),
			}
		}
		return &v3.CheckRequest{
			Attributes: &v3.AttributeContext{
				Request: &v3.AttributeContext_Request{
					Http: &v3.AttributeContext_HttpRequest{
						Path:    path,
						Headers: headers,
						Method:  http.MethodGet,
					},
					Time: timestamppb.Now(),
				},
				MetadataContext: &core.Metadata{
					FilterMetadata: filterMeta,
				},
			},
		}
	}

	// 1. Unset jwtProviderKey: secondary provider carrying api_product_list alone must NOT authenticate.
	srvUnset := newServer("")
	req := makeReq("/hello", nil, map[string]interface{}{
		"secondary": map[string]interface{}{
			"api_product_list": []interface{}{"product1"},
			"application_name": "spoofed-app",
		},
	})
	resp, err := srvUnset.Check(context.Background(), req)
	if err != nil || resp.Status.Code != int32(rpc.UNAUTHENTICATED) {
		t.Fatalf("secondary payload alone: got code=%v err=%v, want UNAUTHENTICATED", resp.GetStatus().GetCode(), err)
	}

	// 2. Unset jwtProviderKey: secondary provider with bogus client_id AND api_product_list must NOT fall back to raw claims.
	req = makeReq("/hello", nil, map[string]interface{}{
		"secondary": map[string]interface{}{
			"client_id":        "bogus-key",
			"api_product_list": []interface{}{"product1"},
			"application_name": "spoofed-app",
		},
	})
	resp, err = srvUnset.Check(context.Background(), req)
	if err != nil || resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Fatalf("bogus api_key_claim with raw claims: got code=%v err=%v, want PERMISSION_DENIED", resp.GetStatus().GetCode(), err)
	}

	// 3. Unset jwtProviderKey: invalid header API key + secondary provider api_product_list must be denied.
	req = makeReq("/hello", map[string]string{"x-api-key": "bad-header-key"}, map[string]interface{}{
		"secondary": map[string]interface{}{
			"api_product_list": []interface{}{"product1"},
			"application_name": "spoofed-app",
		},
	})
	resp, err = srvUnset.Check(context.Background(), req)
	if err != nil || resp.Status.Code != int32(rpc.PERMISSION_DENIED) {
		t.Fatalf("invalid header key + secondary claims: got code=%v err=%v, want PERMISSION_DENIED", resp.GetStatus().GetCode(), err)
	}

	// 4. Unset jwtProviderKey: valid api_key_claim verified by Apigee succeeds.
	req = makeReq("/hello", nil, map[string]interface{}{
		"secondary": map[string]interface{}{
			"client_id":        "valid-key",
			"api_product_list": []interface{}{"spoofed-product"},
		},
	})
	resp, err = srvUnset.Check(context.Background(), req)
	if err != nil || resp.Status.Code != int32(rpc.OK) {
		t.Fatalf("valid api_key_claim: got code=%v err=%v, want OK", resp.GetStatus().GetCode(), err)
	}

	// 5. Unset jwtProviderKey: valid header API key and query API key still accepted.
	req = makeReq("/hello", map[string]string{"x-api-key": "valid-key"}, nil)
	resp, err = srvUnset.Check(context.Background(), req)
	if err != nil || resp.Status.Code != int32(rpc.OK) {
		t.Fatalf("valid header key: got code=%v err=%v, want OK", resp.GetStatus().GetCode(), err)
	}
	req = makeReq("/hello?x-api-key=valid-key", nil, nil)
	resp, err = srvUnset.Check(context.Background(), req)
	if err != nil || resp.Status.Code != int32(rpc.OK) {
		t.Fatalf("valid query key: got code=%v err=%v, want OK", resp.GetStatus().GetCode(), err)
	}

	// 6. Configured jwtProviderKey: Apigee provider claims accepted deterministically even alongside secondary provider.
	srvSet := newServer("apigee")
	for i := 0; i < 30; i++ {
		req = makeReq("/hello", nil, map[string]interface{}{
			"apigee": map[string]interface{}{
				"client_id":        "apigee-client",
				"application_name": "apigee-app",
				"api_product_list": []interface{}{"product1"},
			},
			"secondary": map[string]interface{}{
				"client_id":        "attacker-client",
				"application_name": "attacker-app",
				"api_product_list": []interface{}{"attacker-product"},
			},
		})
		resp, err = srvSet.Check(context.Background(), req)
		if err != nil || resp.Status.Code != int32(rpc.OK) {
			t.Fatalf("iter %d: configured jwtProviderKey: got code=%v err=%v, want OK", i, resp.GetStatus().GetCode(), err)
		}
		meta := resp.GetDynamicMetadata().GetFields()
		if gotClient := meta[headerClientID].GetStringValue(); gotClient != "apigee-client" {
			t.Fatalf("iter %d: got client_id=%q, want apigee-client", i, gotClient)
		}
	}
}
