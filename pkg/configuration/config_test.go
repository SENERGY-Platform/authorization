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


package configuration

import (
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	f()
	os.Stdout = orig
	w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestHandleEnvironmentVarsHidesSecrets(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "hunter2")
	t.Setenv("API_PORT", "8080")

	config := &ConfigStruct{}
	out := captureStdout(t, func() { HandleEnvironmentVars(config) })

	if config.PostgresPassword != "hunter2" {
		t.Fatalf("secret not applied: %q", config.PostgresPassword)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("secret logged: %s", out)
	}
	if !strings.Contains(out, "API_PORT") {
		t.Fatalf("non-secret not logged: %s", out)
	}
}
