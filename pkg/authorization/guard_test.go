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
	"context"
	"fmt"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/persistence"
	"sync"
	"testing"
)

var testSizes = []int{
	10,
	100,
	1000,
}

func BenchmarkAuthorizeList(b *testing.B) {
	guard, cancel, err := setup()
	if err != nil {
		b.Fatal(err)
	}
	defer cancel()
	for _, l := range testSizes {
		list := getList(l)
		b.Run(fmt.Sprintf("Parallel_%d", l), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				guard.AuthorizeList(list, true)
			}
		})
		b.Run(fmt.Sprintf("Sequential_%d", l), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				guard.AuthorizeList(list, false)
			}
		})
	}

}

func setup() (guard *Guard, cancel context.CancelFunc, err error) {
	config, err := configuration.Load("../../config.json")
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	db, err := persistence.New(ctx, wg, config)
	if err != nil {
		return
	}
	guard = NewGuard(config, db)
	return
}

func getList(length int) []*Request {
	l := make([]*Request, length)
	for i := 0; i < length; i++ {
		l[i] = &Request{
			UserId:       "sepl",
			Roles:        []string{"user"},
			Username:     "sepl",
			ClientId:     "test",
			TargetMethod: "GET",
			TargetUri:    "/test",
		}
	}
	return l
}
