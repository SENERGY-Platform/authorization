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
	"errors"

	"github.com/SENERGY-Platform/authorization/pkg/api/util"
	"github.com/SENERGY-Platform/authorization/pkg/authorization"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/model"
	"github.com/gin-gonic/gin"
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

func CheckEndpoints(router *gin.Engine, _ configuration.Config, jwt util.Jwt, guard *authorization.Guard) {
	router.POST("/check", checkHandler(jwt, guard))
}

// checkHandler godoc
// @Summary Check access and return user info
// @Description Validates the JWT from the request body and checks whether access to the given method/URI is permitted. Returns user details on success.
// @Tags check
// @Accept json
// @Produce json
// @Param request body checkRequest true "Check request with authorization header and target"
// @Success 200 {object} checkResponse
// @Failure 400 {string} ErrorResponse
// @Failure 401 {string} ErrorResponse
// @Failure 403 {string} ErrorResponse
// @Router /check [post]
func checkHandler(jwt util.Jwt, guard *authorization.Guard) gin.HandlerFunc {
	return func(c *gin.Context) {
		var checkR checkRequest
		err := c.ShouldBindJSON(&checkR)
		if err != nil {
			c.Error(errors.Join(model.ErrBadRequest, err))
			return
		}
		username, userId, roles, clientId, err := jwt.ParseHeader(checkR.Headers.Authorization)
		if err != nil {
			c.Error(errors.Join(model.GetError(401), err))
			return
		}

		response := checkResponse{
			UserId:   userId,
			Username: username,
			Roles:    roles,
			ClientId: clientId,
		}
		authErr := guard.Authorize(&authorization.Request{
			UserId:       userId,
			Roles:        roles,
			Username:     username,
			ClientId:     clientId,
			TargetMethod: checkR.Headers.TargetMethod,
			TargetUri:    checkR.Headers.TargetUri,
		})

		if authErr == nil {
			c.JSON(200, response)
			return
		}

		c.Error(errors.Join(model.GetError(403), authErr))
	}
}
