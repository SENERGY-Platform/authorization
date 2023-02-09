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
	endpoints = append(endpoints, TestEndpoints)
}

type TestResponse struct {
	Get    bool `json:"GET"`
	Post   bool `json:"POST"`
	Put    bool `json:"PUT"`
	Patch  bool `json:"PATCH"`
	Delete bool `json:"DELETE"`
	Head   bool `json:"HEAD"`
}

func TestEndpoints(router *httprouter.Router, _ configuration.Config, _ util.Jwt, guard *authorization.Guard) {
	router.POST("/test", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		var checkR authorization.Request
		err := json.NewDecoder(request.Body).Decode(&checkR)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(writer).Encode(&errorResponse{Message: "Could not parse request"})
			if err != nil {
				log.Println("ERROR: " + err.Error())
			}
			return
		}

		checkR.TargetMethod = http.MethodGet
		get := guard.Authorize(&checkR)

		checkR.TargetMethod = http.MethodPost
		post := guard.Authorize(&checkR)

		checkR.TargetMethod = http.MethodPut
		put := guard.Authorize(&checkR)

		checkR.TargetMethod = http.MethodPatch
		patch := guard.Authorize(&checkR)

		checkR.TargetMethod = http.MethodDelete
		del := guard.Authorize(&checkR)

		checkR.TargetMethod = http.MethodHead
		head := guard.Authorize(&checkR)

		err = json.NewEncoder(writer).Encode(TestResponse{
			Get:    get == nil,
			Post:   post == nil,
			Put:    put == nil,
			Patch:  patch == nil,
			Delete: del == nil,
			Head:   head == nil,
		})
		if err != nil {
			log.Println("ERROR: " + err.Error())
		}
		return
	})

}
