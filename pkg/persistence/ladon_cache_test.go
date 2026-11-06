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
	"errors"
	"testing"

	"github.com/SENERGY-Platform/authorization/pkg/log"
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/ory/ladon"
	ladonmemory "github.com/ory/ladon/manager/memory"
)

// mapCache behaves like gomemcache: GetMulti returns only the keys it holds and no error for misses.
type mapCache map[string][]byte

func (c mapCache) Set(item *memcache.Item) error {
	c[item.Key] = item.Value
	return nil
}

func (c mapCache) DeleteAll() error {
	clear(c)
	return nil
}

func (c mapCache) GetMulti(keys []string) (map[string]*memcache.Item, error) {
	res := map[string]*memcache.Item{}
	for _, k := range keys {
		if v, ok := c[k]; ok {
			res[k] = &memcache.Item{Key: k, Value: v}
		}
	}
	return res, nil
}

// flakyManager fails FindRequestCandidates while down is set, like a database that cannot be reached.
type flakyManager struct {
	*ladonmemory.MemoryManager
	down bool
}

func (m *flakyManager) FindRequestCandidates(r *ladon.Request) (ladon.Policies, error) {
	if m.down {
		return nil, errors.New("dial tcp: lookup pg-rw: no such host")
	}
	return m.MemoryManager.FindRequestCandidates(r)
}

var allowUserDevices = &ladon.DefaultPolicy{
	ID:        "user-devices",
	Subjects:  []string{"user"},
	Resources: []string{"<^(endpoints:device-manager:devices).*>"},
	Actions:   []string{"GET"},
	Effect:    ladon.AllowAccess,
}

var devicesRequest = ladon.Request{
	Subject:  "user",
	Resource: "endpoints:device-manager:devices?ids=a,b",
	Action:   "GET",
}

func newTestPersistence(t *testing.T) (*Persistence, *flakyManager, mapCache) {
	t.Helper()
	log.InitForTest()
	manager := &flakyManager{MemoryManager: ladonmemory.NewMemoryManager()}
	cache := mapCache{}
	return &Persistence{ladon: &ladon.Ladon{Manager: manager}, mc: cache}, manager, cache
}

func TestEvaluationErrorIsNotCachedAsDenial(t *testing.T) {
	p, manager, cache := newTestPersistence(t)
	if err := manager.Create(allowUserDevices); err != nil {
		t.Fatal(err)
	}

	manager.down = true
	if err := p.IsAllowed(&devicesRequest); err == nil {
		t.Fatal("request allowed although the policies could not be read")
	}
	if len(cache) != 0 {
		t.Fatalf("evaluation error was cached: %v", cache)
	}

	manager.down = false
	if err := p.IsAllowed(&devicesRequest); err != nil {
		t.Fatalf("request still denied after the database recovered: %v", err)
	}
}

func TestDenialIsCached(t *testing.T) {
	p, manager, cache := newTestPersistence(t)

	if err := p.IsAllowed(&devicesRequest); err == nil {
		t.Fatal("request allowed without a policy")
	}
	if len(cache) != 1 {
		t.Fatalf("denial was not cached: %v", cache)
	}

	// Written past Persistence.Create, so the cache is not cleared and must still answer.
	if err := manager.Create(allowUserDevices); err != nil {
		t.Fatal(err)
	}
	if err := p.IsAllowed(&devicesRequest); err == nil {
		t.Fatal("cached denial was not used")
	}
}

func TestIsDecision(t *testing.T) {
	if !isDecision(ladon.ErrRequestDenied) || !isDecision(ladon.ErrRequestForcefullyDenied) {
		t.Fatal("ladon denial not recognised")
	}
	if isDecision(errors.New("connection refused")) {
		t.Fatal("database error taken for a denial")
	}
}
