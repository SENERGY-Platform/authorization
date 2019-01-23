/*
 *    Copyright 2018 InfAI (CC SES)
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

package ladon_test

import (
	"fmt"
	"testing"

	. "github.com/ory/ladon"
	. "github.com/ory/ladon/manager/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A bunch of exemplary policies
var pols = []Policy{
	&DefaultPolicy{
		ID: "1",
		Subjects:  []string{"role:admin"},
		Resources: []string{"/iot-device-repo"},
		Actions:   []string{"POST", "DELETE"},
		Effect:    AllowAccess,
	},
	&DefaultPolicy{
		ID:          "2",
		Subjects:    []string{"role:user"},
		Actions:     []string{"GET"},
		Resources:   []string{"/iot-device-repo"},
		Effect:      AllowAccess,
	}
}

// Some test cases
var cases = []struct {
	description   string
	accessRequest *Request
	expectErr     bool
}{
	{
		description: "should fail because no policy is matching as the owner of the resource 123 is zac, not peter!",
		accessRequest: &Request{
			Subject:  "peter",
			Action:   "delete",
			Resource: "myrn:some.domain.com:resource:123",
			Context: Context{
				"owner":    "zac",
				"clientIP": "127.0.0.1",
			},
		},
		expectErr: true,
	},
	{
		description: "should pass because policy 1 is matching and has effect allow.",
		accessRequest: &Request{
			Subject:  "role:admin",
			Action:   "POST",
			Resource: "/iot-device-repo",
		},
		expectErr: false,
	},
	{
		description: "should pass because user is allowed to GET.",
		accessRequest: &Request{
			Subject:  "role:user",
			Action:   "GET",
			Resource: "/iot-device-repo",
		},
		expectErr: false,
	},
	{
		description: "should fail because user is not allowed to POST to any resource.",
		accessRequest: &Request{
			Subject:  "role:user",
			Action:   "POST",
			Resource: "/iot-device-repo",
		},
		expectErr: true,
	},
}

func TestLadon(t *testing.T) {
	// Instantiate ladon with the default in-memory store.
	warden := &Ladon{Manager: NewMemoryManager()}

	// Add the policies defined above to the memory manager.
	for _, pol := range pols {
		require.Nil(t, warden.Manager.Create(pol))
	}

	for k, c := range cases {
		t.Run(fmt.Sprintf("case=%d-%s", k, c.description), func(t *testing.T) {

			// This is where we ask the warden if the access requests should be granted
			err := warden.IsAllowed(c.accessRequest)

			assert.Equal(t, c.expectErr, err != nil)
		})
	}
}

func TestLadonEmpty(t *testing.T) {
	// If no policy was given, the warden must return an error!
	warden := &Ladon{Manager: NewMemoryManager()}
	assert.NotNil(t, warden.IsAllowed(&Request{}))
}
© 2018 GitHub, Inc.
Terms
Privacy
Security
Status
Help
Contact GitHub
API
Training
Shop
Blog
About