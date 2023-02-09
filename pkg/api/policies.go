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

package api

import (
	"encoding/json"
	"github.com/SENERGY-Platform/authorization/pkg/api/util"
	"github.com/SENERGY-Platform/authorization/pkg/authorization"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/ladon"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
)

const resourceLocation = "/policies"

func init() {
	endpoints = append(endpoints, PoliciesEndpoints)
}

func PoliciesEndpoints(router *httprouter.Router, _ configuration.Config, _ util.Jwt, guard *authorization.Guard) {

	router.GET(resourceLocation, func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		subject := request.URL.Query()["subject"]
		var policies ladon.Policies
		var err error
		if len(subject) != 0 {
			request := &ladon.Request{
				Subject: subject[0],
			}

			// filter for policies that matches the request
			policies, err = guard.Persistence.Ladon.Manager.FindRequestCandidates(request)
			if err != nil {
				http.Error(writer, "error at finding policies to the subject", http.StatusInternalServerError)
				return
			}

		} else {
			policies, err = guard.Persistence.Ladon.Manager.GetAll(1000, 0)
			if err != nil {
				http.Error(writer, "error at getting all policies", http.StatusInternalServerError)
				return
			}
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		err = json.NewEncoder(writer).Encode(policies)
		if err != nil {
			log.Println("ERROR:", err)
			debug.PrintStack()
		}
	})

	router.DELETE(resourceLocation, func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		ids := []string{}

		idQuery := request.URL.Query()["ids"]
		if len(idQuery) > 0 {
			ids = append(ids, strings.Split(idQuery[0], ",")...)
		}

		var bodyIds []string
		err := json.NewDecoder(request.Body).Decode(&bodyIds)
		if err == nil {
			ids = append(ids, bodyIds...)
		}

		if len(ids) == 0 {
			http.Error(writer, "expected policy id", http.StatusBadRequest)
			return
		}

		for _, id := range ids {
			if id == "admin-all" {
				http.Error(writer, "Will not delete policy admin-all: protected policy", http.StatusBadRequest)
				return
			}
			_, err := guard.Persistence.Ladon.Manager.Get(id)
			if err != nil {
				http.Error(writer, "policy with id "+id+" not found", http.StatusNotFound)
				return
			}
		}

		for _, id := range ids {
			err := guard.Persistence.Ladon.Manager.Delete(id)
			if err != nil {
				http.Error(writer, "error at deleting policy", http.StatusInternalServerError)
				return
			}
		}

		writer.WriteHeader(204)
	})

	router.PUT(resourceLocation, func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		var policies []ladon.DefaultPolicy
		err := json.NewDecoder(request.Body).Decode(&policies)
		if err != nil {
			http.Error(writer, "Could not parse policies", http.StatusBadRequest)
			return
		}
		for _, pol := range policies {
			_, err = guard.Persistence.Ladon.Manager.Get(pol.ID)
			if err != nil {
				err = guard.Persistence.Ladon.Manager.Create(&pol)
			} else {
				err = guard.Persistence.Ladon.Manager.Update(&pol)
			}
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		writer.WriteHeader(204)
	})

	router.POST(resourceLocation, func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		var policies []ladon.DefaultPolicy
		err := json.NewDecoder(request.Body).Decode(&policies)
		if err != nil {
			http.Error(writer, "Could not parse policies", http.StatusBadRequest)
			return
		}

		for _, pol := range policies {
			_, err = guard.Persistence.Ladon.Manager.Get(pol.GetID())
			if err == nil {
				http.Error(writer, "Policy with id "+pol.GetID()+" already exists", http.StatusBadRequest)
				return
			}
		}
		for _, pol := range policies {
			err = guard.Persistence.Ladon.Manager.Create(&pol)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		writer.WriteHeader(204)
	})

}
