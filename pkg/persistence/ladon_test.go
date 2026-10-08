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

package persistence

import (
	"strings"
	"testing"

	"github.com/ory/ladon"
)

// legalMemcacheKey mirrors the check in gomemcache, which rejects a whole GetMulti on one bad key.
func legalMemcacheKey(key string) bool {
	if len(key) > 250 {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] <= ' ' || key[i] == 0x7f {
			return false
		}
	}
	return true
}

func TestCacheKeyIsLegalForMemcached(t *testing.T) {
	long := ladon.Request{
		Subject:  "admin user",
		Resource: "endpoints:" + strings.Repeat("device-manager:devices:", 20),
		Action:   "GET",
		Context:  ladon.Context{"note": "with spaces\tand tabs"},
	}
	other := long
	other.Action = "POST"

	k1, err := cacheKey(long)
	if err != nil {
		t.Fatal(err)
	}
	if !legalMemcacheKey(k1) {
		t.Fatalf("illegal memcached key (%d bytes): %q", len(k1), k1)
	}
	k1again, _ := cacheKey(long)
	if k1 != k1again {
		t.Fatal("key is not deterministic")
	}
	k2, _ := cacheKey(other)
	if k1 == k2 {
		t.Fatal("different requests share a key")
	}
}
