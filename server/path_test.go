// Copyright 2026 Google LLC
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

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	libAuth "github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/apigee/apigee-remote-service-golib/v2/quota"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/gogo/googleapis/google/rpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type recordingQuotaMan struct {
	applied []string
}

func (q *recordingQuotaMan) Start() {}
func (q *recordingQuotaMan) Close() {}
func (q *recordingQuotaMan) Apply(auth *libAuth.Context, p product.AuthorizedOperation, args quota.Args) (*quota.Result, error) {
	q.applied = append(q.applied, p.ID)
	return &quota.Result{}, nil
}

func TestCheckPathNormalizationWithRealProductManager(t *testing.T) {
	apiProducts := product.APIResponse{
		APIProducts: []product.APIProduct{
			{
				Name:         "public-legacy",
				DisplayName:  "public-legacy",
				Environments: []string{"env"},
				Attributes: []product.Attribute{
					{Name: product.TargetsAttr, Value: "api"},
				},
				Resources: []string{"/public/**", "/users/*/profile", "/items/*"},
			},
			{
				Name:         "root-product",
				DisplayName:  "root-product",
				Environments: []string{"env"},
				Attributes: []product.Attribute{
					{Name: product.TargetsAttr, Value: "api"},
				},
				Resources: []string{"/"},
			},
			{
				Name:         "quota-ops",
				DisplayName:  "quota-ops",
				Environments: []string{"env"},
				OperationGroup: &product.OperationGroup{
					OperationConfigType: "remoteservice",
					OperationConfigs: []product.OperationConfig{
						{
							APISource: "api",
							Operations: []product.Operation{
								{Resource: "/q/**", Methods: []string{"GET"}},
							},
							Quota: &product.Quota{Limit: "10", Interval: "1", TimeUnit: "minute"},
						},
						{
							APISource: "api",
							Operations: []product.Operation{
								{Resource: "/q/special", Methods: []string{"GET"}},
							},
							Quota: &product.Quota{Limit: "5", Interval: "1", TimeUnit: "minute"},
						},
					},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apiProducts)
	}))
	defer ts.Close()

	baseURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	prodMan, err := product.NewManager(product.Options{
		Client:      ts.Client(),
		BaseURL:     baseURL,
		RefreshRate: time.Hour,
		Org:         "org",
		Env:         "env",
	})
	if err != nil {
		t.Fatalf("product.NewManager: %v", err)
	}
	defer prodMan.Close()

	checkPath := func(t *testing.T, products []string, reqPath string) (rpc.Code, []string) {
		t.Helper()
		authMan := &testAuthMan{}
		authMan.sendAuth(&libAuth.Context{
			ClientID:       "client",
			Application:    "app",
			DeveloperEmail: "dev@example.com",
			APIProducts:    products,
		}, nil)
		quotaMan := &recordingQuotaMan{}
		srv := AuthorizationServer{
			handler: &Handler{
				orgName:      "org",
				envName:      "env",
				apiHeader:    headerAPI,
				apiKeyHeader: "x-api-key",
				authMan:      authMan,
				productMan:   prodMan,
				quotaMan:     quotaMan,
				analyticsMan: &testAnalyticsMan{},
			},
		}
		req := &v3.CheckRequest{
			Attributes: &v3.AttributeContext{
				Request: &v3.AttributeContext_Request{
					Http: &v3.AttributeContext_HttpRequest{
						Path:    reqPath,
						Method:  http.MethodGet,
						Headers: map[string]string{headerAPI: "api"},
					},
					Time: timestamppb.Now(),
				},
			},
		}
		resp, err := srv.Check(context.Background(), req)
		if err != nil {
			t.Fatalf("Check(%q) returned error: %v", reqPath, err)
		}
		return rpc.Code(resp.Status.Code), quotaMan.applied
	}

	deniedCases := []struct {
		name string
		path string
	}{
		{"direct admin", "/admin"},
		{"dotdot literal", "/public/../admin"},
		{"percent-encoded dotdot", "/public/%2e%2e/admin"},
		{"uppercase percent-encoded dotdot", "/public/%2E%2E/admin"},
		{"encoded slash after dotdot", "/public/..%2Fadmin"},
		{"encoded lowercase slash after dotdot", "/public/..%2fadmin"},
		{"encoded backslash after dotdot", "/public/..%5Cadmin"},
		{"encoded lowercase backslash", "/public/..%5cadmin"},
		{"literal backslash traversal", `/public/..\admin`},
		{"matrix param on dotdot", "/public/..;/admin"},
		{"matrix param with kv on dotdot", "/public/..;v=1/admin"},
		{"nested dotdot traversal", "/public/x/%2e%2e/%2e%2e/admin"},
		{"double-encoded dotdot", "/public/%252e%252e/admin"},
		{"triple-encoded dotdot", "/public/%25252e%25252e/admin"},
		{"four-level encoded dotdot exceeds depth", "/public/%2525252e%2525252e/admin"},
		{"rfc3986 keep-%2F traversal", "/public/a%2Fb/%2e%2e/%2e%2e/admin"},
		{"overlong utf8 dotdot", "/public/%c0%ae%c0%ae/admin"},
		{"overlong utf8 slash", "/public/..%c0%afadmin"},
		{"nfkc fullwidth dotdot", "/public/%ef%bc%8e%ef%bc%8e/admin"},
		{"nfkc two-dot leader", "/public/\u2025/admin"},
		{"trailing space on dotdot", "/public/..%20/admin"},
		{"merged slashes traversal", "/public//..//admin"},
		{"opposite direction literal", "/admin/../public/x"},
		{"opposite direction encoded slash", "/admin%2F..%2Fpublic/x"},
		{"single-star dotdot", "/items/.."},
		{"single-star encoded slash", "/users/alice%2Fbob/profile"},
		{"single-star encoded question mark", "/users/alice%3F/profile"},
		{"single-star encoded hash", "/users/alice%23/profile"},
		{"invalid truncated escape", "/public/%2"},
		{"invalid non-hex escape", "/public/%ZZ"},
		{"trailing bare percent", "/public/100%"},
		{"encoded nul control char", "/public/%00foo"},
		{"encoded newline control char", "/public/%0afoo"},
		{"encoded cr control char", "/public/%0dfoo"},
		{"encoded del control char", "/public/%7ffoo"},
		{"overlong utf8 nul", "/public/%c0%80foo"},
		{"raw control char", "/public/a\x00b"},
	}

	for _, tc := range deniedCases {
		t.Run("deny/"+tc.name, func(t *testing.T) {
			code, _ := checkPath(t, []string{"public-legacy"}, tc.path)
			if code != rpc.PERMISSION_DENIED {
				t.Errorf("path %q: got %s, want PERMISSION_DENIED", tc.path, code)
			}
		})
	}

	allowedCases := []struct {
		name     string
		products []string
		path     string
	}{
		{"trailing slash under double-star", []string{"public-legacy"}, "/public/"},
		{"filename containing double dots", []string{"public-legacy"}, "/public/files/v1..v2"},
		{"encoded space", []string{"public-legacy"}, "/public/hello%20world"},
		{"encoded unicode", []string{"public-legacy"}, "/public/caf%C3%A9"},
		{"encoded literal percent", []string{"public-legacy"}, "/public/100%25"},
		{"matrix param inside allowed prefix", []string{"public-legacy"}, "/public/items;v=1"},
		{"single-star normal segment", []string{"public-legacy"}, "/users/alice/profile"},
		{"root resource", []string{"root-product"}, "/"},
	}

	for _, tc := range allowedCases {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			code, _ := checkPath(t, tc.products, tc.path)
			if code != rpc.OK {
				t.Errorf("path %q: got %s, want OK", tc.path, code)
			}
		})
	}

	t.Run("deny/too many interpretations", func(t *testing.T) {
		// Combine all independent decoding and structural transforms (2^9+ > 256).
		bomb := "/public//a\\b;1/c%20/%c0%ae/%ef%bc%8e/%252e/%252f/%255c/d%3fe%23f/./x/../ok"
		if _, err := expandPathInterpretations(bomb); err != errTooManyPathInterpretations {
			t.Fatalf("expandPathInterpretations(bomb) err = %v, want %v", err, errTooManyPathInterpretations)
		}
		code, _ := checkPath(t, []string{"public-legacy"}, bomb)
		if code != rpc.PERMISSION_DENIED {
			t.Errorf("bomb path: got %s, want PERMISSION_DENIED", code)
		}
	})

	t.Run("quota applied across all matched interpretations without duplicates", func(t *testing.T) {
		// Raw path "/q/a/../special" matches only "/q/**"; cleaned "/q/special" matches both "/q/**" and "/q/special".
		code, applied := checkPath(t, []string{"quota-ops"}, "/q/a/../special")
		if code != rpc.OK {
			t.Fatalf("got %s, want OK", code)
		}
		if len(applied) != 2 {
			t.Fatalf("expected 2 unique quotas applied across interpretations, got %d (%v)", len(applied), applied)
		}
	})
}
