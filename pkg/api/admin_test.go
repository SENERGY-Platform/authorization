/*
 *    Copyright 2026 InfAI (CC SES)
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package api

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SENERGY-Platform/authorization/pkg/api/util"
	"github.com/SENERGY-Platform/authorization/pkg/authorization"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/log"
	"github.com/SENERGY-Platform/authorization/pkg/model"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type rsaFixture struct {
	key    *rsa.PrivateKey
	config configuration.Config
}

func newRsaFixture(t *testing.T) rsaFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// Keycloak's realm key is configured as bare base64 DER, without PEM armour.
	return rsaFixture{key: key, config: &configuration.ConfigStruct{JwtSigningMethod: "rsa", JwtSigningKey: base64.StdEncoding.EncodeToString(der)}}
}

func (f rsaFixture) token(t *testing.T, method jwt.SigningMethod, key any, exp time.Time, roles ...string) string {
	t.Helper()
	token, err := jwt.NewWithClaims(method, jwt.MapClaims{
		"sub":                "user-id",
		"preferred_username": "user-name",
		"realm_access":       map[string]any{"roles": roles},
		"azp":                "frontend",
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"exp":                exp.Unix(),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func newTestRouter(config configuration.Config, register ...func(*gin.Engine, configuration.Config, util.Jwt, *authorization.Guard)) *gin.Engine {
	log.InitForTest()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Recovery turns a handler that reaches the missing persistence into a 500 instead of crashing the test.
	router.Use(ErrorHandler(model.GetStatusCode, ", "), gin.Recovery())
	guard := authorization.NewGuard(config, nil)
	for _, r := range register {
		r(router, config, util.NewJwt(config), guard)
	}
	return router
}

func TestRequireAdmin(t *testing.T) {
	f := newRsaFixture(t)
	hour := time.Now().Add(time.Hour)
	admin := f.token(t, jwt.SigningMethodRS256, f.key, hour, "user", "admin")
	user := f.token(t, jwt.SigningMethodRS256, f.key, hour, "user")
	expiredAdmin := f.token(t, jwt.SigningMethodRS256, f.key, time.Now().Add(-time.Minute), "admin")
	noneAdmin := f.token(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, hour, "admin")
	hmacAdmin := f.token(t, jwt.SigningMethodHS256, []byte(f.config.JwtSigningKey), hour, "admin")

	cases := []struct {
		name       string
		header     string
		credential string
		wantStatus int
	}{
		{"no header", "", "", http.StatusUnauthorized},
		{"token without scheme", admin, admin, http.StatusUnauthorized},
		{"malformed token", "Bearer not.a.jwt", "not.a.jwt", http.StatusUnauthorized},
		{"basic credentials", "Basic dXNlcjpzZWNyZXQ=", "dXNlcjpzZWNyZXQ=", http.StatusUnauthorized},
		{"expired admin token", "Bearer " + expiredAdmin, expiredAdmin, http.StatusUnauthorized},
		{"alg none admin token", "Bearer " + noneAdmin, noneAdmin, http.StatusUnauthorized},
		{"HS256 admin token keyed with the public key", "Bearer " + hmacAdmin, hmacAdmin, http.StatusUnauthorized},
		{"valid token without admin", "Bearer " + user, user, http.StatusForbidden},
		{"valid token with admin", "Bearer " + admin, admin, http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			router := newTestRouter(f.config)
			var logs bytes.Buffer
			log.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
			router.GET("/protected", requireAdmin(util.NewJwt(f.config), func(c *gin.Context) {
				reached = true
				c.Status(http.StatusNoContent)
			}))

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if wantReached := tc.wantStatus == http.StatusNoContent; reached != wantReached {
				t.Fatalf("handler reached: %v, want %v", reached, wantReached)
			}
			if !reached {
				var body struct{ Errors []string }
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Errors) == 0 {
					t.Fatalf("response is not in the error model: %q", rec.Body.String())
				}
				if !strings.Contains(logs.String(), `"msg":"Admin auth`) {
					t.Fatalf("rejection not logged: %s", logs.String())
				}
			}
			if tc.credential != "" && strings.Contains(logs.String(), tc.credential) {
				t.Errorf("log contains the credential: %s", logs.String())
			}
			if tc.credential != "" && strings.Contains(rec.Body.String(), tc.credential) {
				t.Errorf("response contains the credential: %s", rec.Body.String())
			}
		})
	}
}

// publicRoutes are the only routes reachable without an admin token.
var publicRoutes = map[string]bool{
	"POST /check":   true,
	"POST /allowed": true,
	"GET /doc":      true,
}

func TestEveryNonPublicRouteRequiresAdmin(t *testing.T) {
	f := newRsaFixture(t)
	user := f.token(t, jwt.SigningMethodRS256, f.key, time.Now().Add(time.Hour), "user")
	router := newTestRouter(f.config, endpoints...)

	checked := 0
	for _, route := range router.Routes() {
		name := route.Method + " " + route.Path
		if publicRoutes[name] {
			continue
		}
		checked++
		t.Run(name, func(t *testing.T) {
			for header, want := range map[string]int{"": http.StatusUnauthorized, "Bearer " + user: http.StatusForbidden} {
				req := httptest.NewRequest(route.Method, route.Path, strings.NewReader("[]"))
				if header != "" {
					req.Header.Set("Authorization", header)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != want {
					t.Errorf("status %d, want %d: %s", rec.Code, want, rec.Body.String())
				}
			}
		})
	}
	// GET, PUT, POST, DELETE /policies, POST /test and GET /access.
	if checked != 6 {
		t.Fatalf("checked %d admin routes, want 6", checked)
	}
}

func TestAdminReachesHandlers(t *testing.T) {
	f := newRsaFixture(t)
	admin := f.token(t, jwt.SigningMethodRS256, f.key, time.Now().Add(time.Hour), "admin")
	router := newTestRouter(f.config, endpoints...)

	// Each request fails validation inside the handler before it touches persistence, so a 400 proves the handler ran.
	cases := []struct {
		method, target, body, wantError string
	}{
		{http.MethodDelete, "/policies?ids=admin-all", "", "protected policy"},
		{http.MethodPut, "/policies", "{", "bad request"},
		{http.MethodPost, "/policies", "{", "bad request"},
		{http.MethodPost, "/test", "{", "bad request"},
		{http.MethodGet, "/access", "{", "bad request"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+admin)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.wantError) {
				t.Fatalf("status %d, body %s; want 400 with %q", rec.Code, rec.Body.String(), tc.wantError)
			}
		})
	}
}

func TestKongEndpointsNeedNoAdmin(t *testing.T) {
	f := newRsaFixture(t)
	user := f.token(t, jwt.SigningMethodRS256, f.key, time.Now().Add(time.Hour), "user")
	router := newTestRouter(f.config, endpoints...)

	// Kong sends the user's token in the /check body, not in the Authorization header of the request.
	// OPTIONS is allowed for any authenticated user without consulting the policies.
	checkBody, _ := json.Marshal(checkRequest{Headers: headers{TargetMethod: http.MethodOptions, TargetUri: "/devices", Authorization: "Bearer " + user}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(checkBody)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"userID":"user-id"`) {
		t.Fatalf("/check: status %d, body %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/allowed", strings.NewReader("[]"))
	req.Header.Set("Authorization", "Bearer "+user)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/allowed: status %d, body %s", rec.Code, rec.Body.String())
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"allowed":null}` {
		t.Fatalf("/allowed: body %s", body)
	}
}
