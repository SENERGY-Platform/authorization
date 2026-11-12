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

package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"slices"
	"testing"
	"time"

	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/log"
	"github.com/golang-jwt/jwt/v5"
)

func testClaims(exp time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"sub":                "user-id",
		"preferred_username": "user-name",
		"realm_access":       map[string]any{"roles": []string{"user", "admin"}},
		"azp":                "frontend",
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"exp":                exp.Unix(),
	}
}

func sign(t *testing.T, method jwt.SigningMethod, claims jwt.MapClaims, key any) string {
	t.Helper()
	token, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestJwtParse(t *testing.T) {
	log.InitForTest()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	valid := testClaims(time.Now().Add(time.Hour))
	futureIat := testClaims(time.Now().Add(time.Hour))
	futureIat["iat"] = time.Now().Add(time.Hour).Unix()
	noAzp := testClaims(time.Now().Add(time.Hour))
	delete(noAzp, "azp")

	cases := []struct {
		name    string
		method  string
		key     string
		token   string
		wantErr bool
	}{
		{"valid RS256, key without PEM armour", "rsa", base64.StdEncoding.EncodeToString(der), sign(t, jwt.SigningMethodRS256, valid, key), false},
		{"valid RS256, key with PEM armour", "rsa", string(publicPem), sign(t, jwt.SigningMethodRS256, valid, key), false},
		{"valid RS512", "rsa", string(publicPem), sign(t, jwt.SigningMethodRS512, valid, key), false},
		{"alg none", "rsa", string(publicPem), sign(t, jwt.SigningMethodNone, valid, jwt.UnsafeAllowNoneSignatureType), true},
		{"HS256 keyed with the public key", "rsa", string(publicPem), sign(t, jwt.SigningMethodHS256, valid, publicPem), true},
		{"HS256 keyed with the configured key string", "rsa", base64.StdEncoding.EncodeToString(der), sign(t, jwt.SigningMethodHS256, valid, []byte(base64.StdEncoding.EncodeToString(der))), true},
		{"PS256", "rsa", string(publicPem), sign(t, jwt.SigningMethodPS256, valid, key), true},
		{"foreign RSA key", "rsa", string(publicPem), sign(t, jwt.SigningMethodRS256, valid, otherKey), true},
		{"expired", "rsa", string(publicPem), sign(t, jwt.SigningMethodRS256, testClaims(time.Now().Add(-time.Minute)), key), true},
		{"issued in the future", "rsa", string(publicPem), sign(t, jwt.SigningMethodRS256, futureIat, key), true},
		{"missing azp", "rsa", string(publicPem), sign(t, jwt.SigningMethodRS256, noAzp, key), true},
		{"valid HS256 under hmac", "hmac", "hmac-secret", sign(t, jwt.SigningMethodHS256, valid, []byte("hmac-secret")), false},
		{"RS256 under hmac", "hmac", "hmac-secret", sign(t, jwt.SigningMethodRS256, valid, key), true},
		{"HS256 with another secret under hmac", "hmac", "hmac-secret", sign(t, jwt.SigningMethodHS256, valid, []byte("other-secret")), true},
		{"unknown signing method in config", "", string(publicPem), sign(t, jwt.SigningMethodRS256, valid, key), true},
		{"unknown signing method in config, alg none", "ecdsa", string(publicPem), sign(t, jwt.SigningMethodNone, valid, jwt.UnsafeAllowNoneSignatureType), true},
		{"unknown signing method in config, HS256 with empty key", "ecdsa", "", sign(t, jwt.SigningMethodHS256, valid, []byte{}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := NewJwt(&configuration.ConfigStruct{JwtSigningMethod: tc.method, JwtSigningKey: tc.key})
			username, userId, roles, clientId, err := j.ParseHeader("Bearer " + tc.token)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("token accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("token rejected: %v", err)
			}
			if username != "user-name" || userId != "user-id" || clientId != "frontend" || !slices.Equal(roles, []string{"user", "admin"}) {
				t.Fatalf("unexpected claims: %q %q %v %q", username, userId, roles, clientId)
			}
		})
	}
}
