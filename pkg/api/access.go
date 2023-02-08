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
	"github.com/SENERGY-Platform/authorization/pkg/authorization"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/ladon"
	"net/http"
)

func init() {
	endpoints = append(endpoints, AccessEndpoint)
}

type KongMessage struct {
	Result bool   `json:"result"`
	Error  string `json:"error"`
}

func AccessEndpoint(router *httprouter.Router, _ configuration.Config, _ util.Jwt, guard *authorization.Guard) {
	router.GET("/access", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		writer.Header().Set("Content-Type", "application/json")
		var ladonRequest ladon.Request

		err := json.NewDecoder(request.Body).Decode(&ladonRequest)
		if err != nil {
			writer.WriteHeader(400)
			return
		}

		var message KongMessage
		err = guard.IsAllowed(&ladonRequest)
		if err != nil {
			message = KongMessage{
				false,
				err.Error(),
			}
		} else {
			message = KongMessage{
				true,
				"",
			}
		}

		err = json.NewEncoder(writer).Encode(message)
		if err != nil {
			fmt.Println("ERROR: " + err.Error())
		}
	})

}
