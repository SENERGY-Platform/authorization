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

func CheckEndpoints(router *httprouter.Router, _ configuration.Config, jwt util.Jwt, guard *authorization.Guard) {
	router.POST("/check", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		var checkR checkRequest
		err := json.NewDecoder(request.Body).Decode(&checkR)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(writer).Encode(&errorResponse{Message: "Could not parse request"})
			if err != nil {
				log.Println("ERROR: " + err.Error())
			}
			return
		}
		username, userId, roles, clientId, err := jwt.ParseHeader(checkR.Headers.Authorization)
		if err != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			err = json.NewEncoder(writer).Encode(&errorResponse{Message: err.Error()})
			if err != nil {
				log.Println("ERROR: " + err.Error())
			}
			return
		}

		response := checkResponse{
			UserId:   userId,
			Username: username,
			Roles:    roles,
			ClientId: clientId,
		}
		err = guard.Authorize(&authorization.Request{
			UserId:       userId,
			Roles:        roles,
			Username:     username,
			ClientId:     clientId,
			TargetMethod: checkR.Headers.TargetMethod,
			TargetUri:    checkR.Headers.TargetUri,
		})

		if err == nil {
			err = json.NewEncoder(writer).Encode(response)
			if err != nil {
				log.Println("ERROR: " + err.Error())
			}
			return
		}

		writer.WriteHeader(http.StatusForbidden)
		err = json.NewEncoder(writer).Encode(&errorResponse{Message: "Forbidden"})
		if err != nil {
			log.Println("ERROR: " + err.Error())
		}
	})

}
