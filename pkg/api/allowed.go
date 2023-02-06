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
	"fmt"
	"github.com/SENERGY-Platform/authorization/pkg/api/util"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/persistence/sql"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/ladon"
	"net/http"
	"strings"
)

func init() {
	endpoints = append(endpoints, AllowedEndpoints)
}

type allowedQuestion struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
}

type allowedResponse struct {
	Allowed []bool `json:"allowed"`
}

func AllowedEndpoints(router *httprouter.Router, config configuration.Config, jwt util.Jwt, persistence *sql.Persistence) {
	router.POST("/allowed", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		writer.Header().Set("Content-Type", "application/json")
		var allowedQuestions []allowedQuestion
		err := json.NewDecoder(request.Body).Decode(&allowedQuestions)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(writer).Encode(&errorResponse{Message: "Could not parse request"})
			fmt.Println(err.Error(), http.StatusBadRequest)
			return
		}
		username, _, roles, _, err := jwt.ParseHeader(request.Header.Get("Authorization"))
		if err != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(writer).Encode(&errorResponse{Message: err.Error()})
			fmt.Println(err.Error(), http.StatusUnauthorized)
			return
		}

		subjects := append(roles, username)

		var resp allowedResponse

		for _, allowedQuestion := range allowedQuestions {
			r := ladon.Request{
				Resource: "endpoints" + strings.ReplaceAll(allowedQuestion.Endpoint, "/", ":"),
				Action:   allowedQuestion.Method,
			}
			resp.Allowed = append(resp.Allowed, isAllowed(config, subjects, r, persistence))
		}

		json.NewEncoder(writer).Encode(resp)
	})
}

func isAllowed(config configuration.Config, subjects []string, r ladon.Request, persistence *sql.Persistence) bool {
	if r.Action == http.MethodOptions {
		// OPTIONS is allowed for authenticated users
		if config.Debug {
			fmt.Println("allowed options")
		}
		return true
	}

	for _, role := range subjects {
		if role == "admin" {
			// admin is allowed everything
			if config.Debug {
				fmt.Println("allowed admin")
			}
			return true
		}
	}

	for _, subject := range subjects {
		r.Subject = subject
		err := persistence.Ladon.IsAllowed(&r)
		if err == nil {
			return true
		}
	}
	return false
}
