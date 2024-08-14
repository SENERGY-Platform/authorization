/*
 *    Copyright 2024 InfAI (CC SES)
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

package memcache

import (
	"log"
	"strings"
	"sync"

	upstream "github.com/bradfitz/gomemcache/memcache"
)

// A bradfitz/gomemcache/memcache wrapper that automatically tries to reconnect once connection drops
type Memcache struct {
	mc      *upstream.Client
	servers []string
	mux     sync.Mutex
}

func New(servers []string) (*Memcache, error) {
	m := &Memcache{
		servers: servers,
		mux:     sync.Mutex{},
	}
	err := m.reconnect()
	return m, err
}

func (m *Memcache) reconnect() error {
	log.Println("(Re-)connecting to memcached")
	if m.mc != nil {
		err := m.mc.Close()
		if err != nil {
			return err
		}
	}
	m.mc = upstream.New(m.servers...)
	return nil
}

func (m *Memcache) Set(item *upstream.Item) error {
	_, err := withReconnectRetry(m, func() (any, error) { return nil, m.mc.Set(item) })
	return err
}

func (m *Memcache) DeleteAll() error {
	_, err := withReconnectRetry(m, func() (any, error) { return nil, m.mc.DeleteAll() })
	return err
}

func (m *Memcache) GetMulti(keys []string) (map[string]*upstream.Item, error) {
	return withReconnectRetry(m, func() (map[string]*upstream.Item, error) { return m.mc.GetMulti(keys) })
}

func withReconnectRetry[T any](m *Memcache, cmd func() (T, error)) (t T, err error) {
	t, err = cmd()
	if err != nil && strings.Contains(err.Error(), "no servers configured or available") {
		defer m.mux.Unlock()
		locked := m.mux.TryLock()
		if !locked {
			m.mux.Lock()
			t, err = cmd() // as the mutex was already locked, reconnect was likely called and cmd might work now
			if err == nil {
				return
			}
		}
		err = m.reconnect()
		if err != nil {
			return t, err
		}
		t, err = cmd()
	}
	return t, err
}
