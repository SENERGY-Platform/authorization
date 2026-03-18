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
	endpoints = append(endpoints, AllowedEndpoints)
}

type allowedQuestion struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
}

type allowedResponse struct {
	Allowed []bool `json:"allowed"`
}

func AllowedEndpoints(router *gin.Engine, _ configuration.Config, jwt util.Jwt, guard *authorization.Guard) {
	router.POST("/allowed", allowedHandler(jwt, guard))
}

// allowedHandler godoc
// @Summary Check multiple access rights
// @Description Evaluates whether the authenticated user is allowed to access a list of method+endpoint combinations.
// @Tags allowed
// @Accept json
// @Produce json
// @Param questions body []allowedQuestion true "List of method/endpoint pairs to check"
// @Success 200 {object} allowedResponse
// @Failure 400 {string} ErrorResponse
// @Failure 401 {string} ErrorResponse
// @Router /allowed [post]
func allowedHandler(jwt util.Jwt, guard *authorization.Guard) gin.HandlerFunc {
	return func(c *gin.Context) {
		var allowedQuestions []allowedQuestion
		err := c.ShouldBindJSON(&allowedQuestions)
		if err != nil {
			c.Error(errors.Join(model.ErrBadRequest, err))
			return
		}
		username, userId, roles, clientId, err := jwt.ParseHeader(c.GetHeader("Authorization"))
		if err != nil {
			c.Error(errors.Join(model.GetError(401), err))
			return
		}

		var resp allowedResponse

		list := []*authorization.Request{}

		for _, allowedQuestion := range allowedQuestions {
			list = append(list, &authorization.Request{
				UserId:       userId,
				Roles:        roles,
				Username:     username,
				ClientId:     clientId,
				TargetMethod: allowedQuestion.Method,
				TargetUri:    allowedQuestion.Endpoint,
			})
		}
		res := guard.AuthorizeList(list, false)

		for _, err := range res {
			if err == nil {
				resp.Allowed = append(resp.Allowed, true)
			} else {
				resp.Allowed = append(resp.Allowed, false)
			}
		}

		c.JSON(200, resp)
	}
}
