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
	endpoints = append(endpoints, CheckEndpoints)
}

type errorResponse struct {
	Message string `json:"message"`
}
type checkResponse struct {
	UserId   string   `json:"userID"`
	Roles    []string `json:"roles"`
	Username string   `json:"username"`
	ClientId string   `json:"clientID"`
}

type checkRequest struct {
	Headers headers `json:"headers"`
}

type headers struct {
	TargetMethod  string `json:"target_method"`
	TargetUri     string `json:"target_uri"`
	Authorization string `json:"authorization"`
}

func CheckEndpoints(router *httprouter.Router, config configuration.Config, jwt util.Jwt, persistence *sql.Persistence) {
	router.POST("/check", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		var checkR checkRequest
		err := json.NewDecoder(request.Body).Decode(&checkR)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(writer).Encode(&errorResponse{Message: "Could not parse request"})
			fmt.Println(err.Error(), http.StatusBadRequest)
			return
		}
		username, user, roles, clientId, err := jwt.ParseHeader(checkR.Headers.Authorization)
		if err != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(writer).Encode(&errorResponse{Message: err.Error()})
			fmt.Println(err.Error(), http.StatusUnauthorized)
			return
		}

		response := checkResponse{
			UserId:   user,
			Username: username,
			Roles:    roles,
			ClientId: clientId,
		}
		r := ladon.Request{
			Resource: "endpoints" + strings.ReplaceAll(checkR.Headers.TargetUri, "/", ":"),
			Action:   checkR.Headers.TargetMethod,
		}

		if r.Action == http.MethodOptions {
			// OPTIONS is allowed for authenticated users
			err = json.NewEncoder(writer).Encode(response)
			if config.Debug {
				fmt.Println("allowed debug")
			}
			return
		}

		for _, role := range roles {
			if role == "admin" {
				// admin is allowed everything
				err = json.NewEncoder(writer).Encode(response)
				if config.Debug {
					fmt.Println("allowed admin")
				}
				return
			}
		}

		subjects := append(roles, username)

		for _, subject := range subjects {
			r.Subject = subject
			err := persistence.Ladon.IsAllowed(&r)
			if err == nil {
				err = json.NewEncoder(writer).Encode(response)
				return
			}
		}

		fmt.Println(http.StatusForbidden)
		writer.WriteHeader(http.StatusForbidden)
		err = json.NewEncoder(writer).Encode(&errorResponse{Message: "Forbidden"})
	})

}
