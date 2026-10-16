/*
 * Copyright 2026 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SENERGY-Platform/authorization/pkg/api/util"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/log"
	"github.com/SENERGY-Platform/authorization/pkg/model"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func TestCheckUnauthorizedKeepsCredentialOutOfLogAndResponse(t *testing.T) {
	foreignToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user-1", "exp": 1700000000}).SignedString([]byte("foreign-key"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		header     string
		credential string
		wantLog    []string
	}{
		{"basic", "Basic dXNlcjpzZWNyZXQ=", "dXNlcjpzZWNyZXQ=", []string{`"authScheme":"Basic"`}},
		{"jwt with foreign key", "Bearer " + foreignToken, foreignToken, []string{`"authScheme":"Bearer"`, `"sub":"user-1"`}},
		{"no scheme", "plain-credential-value", "plain-credential-value", nil},
		{"credential as scheme", "user:secret-value x", "user:secret-value", []string{`"authScheme":"other"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			log.Logger = slog.New(slog.NewJSONHandler(&logs, nil))

			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.Use(ErrorHandler(model.GetStatusCode, ", "))
			config := &configuration.ConfigStruct{JwtSigningMethod: "hmac", JwtSigningKey: "platform-key"}
			CheckEndpoints(router, config, util.NewJwt(config), nil)

			body, _ := json.Marshal(checkRequest{Headers: headers{TargetMethod: "GET", TargetUri: "/devices", Authorization: tc.header}})
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body)))

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", rec.Code)
			}
			if strings.Contains(logs.String(), tc.credential) {
				t.Errorf("log contains the credential: %s", logs.String())
			}
			if strings.Contains(rec.Body.String(), tc.credential) {
				t.Errorf("response contains the credential: %s", rec.Body.String())
			}
			for _, want := range tc.wantLog {
				if !strings.Contains(logs.String(), want) {
					t.Errorf("log lacks %s: %s", want, logs.String())
				}
			}
		})
	}
}
