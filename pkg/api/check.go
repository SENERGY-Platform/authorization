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
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/persistence/sql"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/ladon"
	"net/http"
	"strings"
)

func init() {
	endpoints = append(endpoints, CheckEndpoints)
}

type checkResponse struct {
	UserId string   `json:"userId"`
	Roles  []string `json:"roles"`
}

type checkRequest struct {
	TargetMethod string `json:"target_method"`
	TargetUri    string `json:"target_uri"`
}

func CheckEndpoints(router *httprouter.Router, config configuration.Config, jwt util.Jwt, persistence *sql.Persistence) {
	router.POST("/check", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		username, user, roles, err := jwt.ParseRequest(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusUnauthorized)
			return
		}

		decoder := json.NewDecoder(request.Body)
		checkR := new(checkRequest)
		err = decoder.Decode(&checkR)
		if err != nil {
			http.Error(writer, "Could not parse request", http.StatusBadRequest)
			return
		}

		response := checkResponse{
			UserId: user,
			Roles:  roles,
		}
		r := ladon.Request{
			Resource: "endpoints" + strings.ReplaceAll(checkR.TargetUri, "/", ":"),
			Action:   checkR.TargetMethod,
		}

		if r.Action == http.MethodOptions {
			// OPTIONS is allowed for authenticated users
			writer.Header().Set("Content-Type", "application/json; charset=utf-8")
			err = json.NewEncoder(writer).Encode(response)
			return
		}

		subjects := append(roles, username)

		for _, subject := range subjects {
			r.Subject = subject
			err := persistence.Ladon.IsAllowed(&r)
			if err == nil {
				writer.Header().Set("Content-Type", "application/json; charset=utf-8")
				err = json.NewEncoder(writer).Encode(response)
				return
			}
		}

		writer.WriteHeader(403)
	})

}
