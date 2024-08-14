/*
 *    Copyright 2023 InfAI (CC SES)
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
	"encoding/json"
	"log"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/ory/ladon"
)

var bTrue byte = 1
var bFalse byte = 0

// Create persists the policy.
func (p *Persistence) Create(policy ladon.Policy) error {
	err := p.mc.DeleteAll()
	if err != nil {
		return err
	}
	return p.ladon.Manager.Create(policy)
}

// Update updates an existing policy.
func (p *Persistence) Update(policy ladon.Policy) error {
	err := p.mc.DeleteAll()
	if err != nil {
		return err
	}
	return p.ladon.Manager.Update(policy)
}

// Get retrieves a policy.
func (p *Persistence) Get(id string) (ladon.Policy, error) {
	return p.ladon.Manager.Get(id)
}

// Delete removes a policy.
func (p *Persistence) Delete(id string) error {
	err := p.mc.DeleteAll()
	if err != nil {
		return err
	}
	return p.ladon.Manager.Delete(id)
}

// GetAll retrieves all policies.
func (p *Persistence) GetAll(limit, offset int64) (ladon.Policies, error) {
	return p.ladon.Manager.GetAll(limit, offset)
}

// FindRequestCandidates returns candidates that could match the request object. It either returns
// a set that exactly matches the request, or a superset of it. If an error occurs, it returns nil and
// the error.
func (p *Persistence) FindRequestCandidates(r *ladon.Request) (ladon.Policies, error) {
	return p.ladon.Manager.FindRequestCandidates(r)
}

func (p *Persistence) IsAnyAllowed(r []ladon.Request) (err error) {
	b := make([]string, len(r))
	for i := range r {
		bytes, err := json.Marshal(r[i])
		if err != nil {
			return err
		}
		b[i] = string(bytes)
	}

	items, err := p.mc.GetMulti(b)
	if err == nil {
		for _, v := range items {
			allowed := len(v.Value) == 1 && v.Value[0] == bTrue
			if allowed {
				return nil
			}
		}
		if len(items) == len(r) {
			return ladon.ErrRequestDenied
		}
	}

	for i := range r {
		ladonErr := p.ladon.IsAllowed(&r[i])
		item := &memcache.Item{
			Key: b[i],
		}
		if ladonErr == nil {
			item.Value = []byte{bTrue}
		} else {
			item.Value = []byte{bFalse}
		}
		err = p.mc.Set(item)
		if err != nil && (p.debounceMcError == nil || time.Now().Sub(*p.debounceMcError) > time.Minute) {
			log.Println("WARN: Could not update cache: " + err.Error())
			now := time.Now()
			p.debounceMcError = &now
		}
		if ladonErr == nil {
			return nil
		}
	}

	return ladon.ErrRequestDenied
}

func (p *Persistence) IsAllowed(r *ladon.Request) (err error) {
	return p.IsAnyAllowed([]ladon.Request{*r})
}
