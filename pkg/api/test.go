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
	"errors"

	"github.com/SENERGY-Platform/authorization/pkg/api/util"
	"github.com/SENERGY-Platform/authorization/pkg/authorization"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/model"
	"github.com/gin-gonic/gin"
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

func TestEndpoints(router *gin.Engine, _ configuration.Config, _ util.Jwt, guard *authorization.Guard) {
	router.POST("/test", func(c *gin.Context) {
		var checkRequest authorization.Request
		if err := c.ShouldBindJSON(&checkRequest); err != nil {
			c.Error(errors.Join(model.ErrBadRequest, err))
			return
		}

		checkRequest.TargetMethod = "GET"
		getErr := guard.Authorize(&checkRequest)

		checkRequest.TargetMethod = "POST"
		postErr := guard.Authorize(&checkRequest)

		checkRequest.TargetMethod = "PUT"
		putErr := guard.Authorize(&checkRequest)

		checkRequest.TargetMethod = "PATCH"
		patchErr := guard.Authorize(&checkRequest)

		checkRequest.TargetMethod = "DELETE"
		deleteErr := guard.Authorize(&checkRequest)

		checkRequest.TargetMethod = "HEAD"
		headErr := guard.Authorize(&checkRequest)

		c.JSON(200, TestResponse{
			Get:    getErr == nil,
			Post:   postErr == nil,
			Put:    putErr == nil,
			Patch:  patchErr == nil,
			Delete: deleteErr == nil,
			Head:   headErr == nil,
		})
	})
}
