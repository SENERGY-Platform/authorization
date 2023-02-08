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
	"log"
	"net/http"
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

func AllowedEndpoints(router *httprouter.Router, _ configuration.Config, jwt util.Jwt, guard *authorization.Guard) {
	router.POST("/allowed", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		writer.Header().Set("Content-Type", "application/json")
		var allowedQuestions []allowedQuestion
		err := json.NewDecoder(request.Body).Decode(&allowedQuestions)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(writer).Encode(&errorResponse{Message: "Could not parse request"})
			if err != nil {
				log.Println("ERROR: " + err.Error())
			}
			return
		}
		username, userId, roles, clientId, err := jwt.ParseHeader(request.Header.Get("Authorization"))
		if err != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			err = json.NewEncoder(writer).Encode(&errorResponse{Message: err.Error()})
			if err != nil {
				log.Println("ERROR: " + err.Error())
			}
			return
		}

		var resp allowedResponse

		for _, allowedQuestion := range allowedQuestions {
			err = guard.Authorize(&authorization.Request{
				UserId:       userId,
				Roles:        roles,
				Username:     username,
				ClientId:     clientId,
				TargetMethod: allowedQuestion.Method,
				TargetUri:    allowedQuestion.Endpoint,
			})
			if err == nil {
				resp.Allowed = append(resp.Allowed, true)
			} else {
				resp.Allowed = append(resp.Allowed, false)
			}
		}

		err = json.NewEncoder(writer).Encode(resp)
		if err != nil {
			log.Println("ERROR: " + err.Error())
		}
	})
}
