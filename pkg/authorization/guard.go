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

package authorization

import (
	"errors"
	"fmt"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/persistence/sql"
	"github.com/ory/ladon"
	"net/http"
	"strings"
	"sync"
)

type Request struct {
	UserId       string   `json:"userID"`
	Roles        []string `json:"roles"`
	Username     string   `json:"username"`
	ClientId     string   `json:"clientID"`
	TargetMethod string   `json:"target_method"`
	TargetUri    string   `json:"target_uri"`
}

type Guard struct {
	config      configuration.Config
	Persistence *sql.Persistence
}

func NewGuard(config configuration.Config, persistence *sql.Persistence) *Guard {
	return &Guard{
		config:      config,
		Persistence: persistence,
	}
}

func (g *Guard) Authorize(checkR *Request) error {
	r := ladon.Request{
		Resource: "endpoints" + strings.ReplaceAll(checkR.TargetUri, "/", ":"),
		Action:   checkR.TargetMethod,
	}

	if r.Action == http.MethodOptions {
		// OPTIONS is allowed for authenticated users
		if g.config.Debug {
			fmt.Println("allowed OPTIONS")
		}
		return nil
	}

	for _, role := range checkR.Roles {
		if role == "admin" {
			// admin is allowed everything
			return nil
		}
	}

	r.Subject = checkR.ClientId
	err := g.Persistence.Ladon.IsAllowed(&r)
	if err != nil {
		return err
	}

	subjects := append(checkR.Roles, checkR.Username)

	for _, subject := range subjects {
		r.Subject = subject
		err := g.Persistence.Ladon.IsAllowed(&r)
		if err == nil {
			return nil
		}
	}
	return errors.New("unauthorized")
}

func (g *Guard) AuthorizeList(checkR []*Request, parallel bool) []error {
	res := make([]error, len(checkR))
	wg := sync.WaitGroup{}
	wg.Add(len(checkR))
	f := func(i int, r *Request) {
		res[i] = g.Authorize(r)
		wg.Done()
	}

	for i, r := range checkR {
		i := i
		if parallel {
			go f(i, r)
		} else {
			f(i, r)
		}
	}
	wg.Wait()
	return res
}

func (g *Guard) IsAllowed(ladonRequest *ladon.Request) error {
	return g.Persistence.Ladon.IsAllowed(ladonRequest)
}
