/*
 *    Copyright 2020 InfAI (CC SES)
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

package sql

import (
	"github.com/ory/ladon"
	"log"
)

func (this *Persistence) migration() (err error) {
	// Create admin policy
	var pol = &ladon.DefaultPolicy{
		ID:          "admin-all",
		Description: "init policy for role admin",
		Subjects:    []string{"admin"},
		Resources:   []string{"<.*>"},
		Actions:     []string{"POST", "GET", "DELETE", "PATCH", "PUT", "HEAD"},
		Effect:      ladon.AllowAccess,
	}
	_, err = this.Ladon.Manager.Get(pol.ID)
	if err == nil {
		err = this.Ladon.Manager.Update(pol)
	} else {
		err = this.Ladon.Manager.Create(pol)
	}
	if err != nil {
		log.Fatal("Could not create initial policy: ", err)
		return err
	}

	return err
}
