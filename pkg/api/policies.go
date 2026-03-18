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
	"strings"

	"github.com/SENERGY-Platform/authorization/pkg/api/util"
	"github.com/SENERGY-Platform/authorization/pkg/authorization"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/model"
	"github.com/gin-gonic/gin"
	"github.com/ory/ladon"
)

const resourceLocation = "/policies"

func init() {
	endpoints = append(endpoints, PoliciesEndpoints)
}

func PoliciesEndpoints(router *gin.Engine, _ configuration.Config, _ util.Jwt, guard *authorization.Guard) {
	router.GET(resourceLocation, func(c *gin.Context) {
		subject := c.Query("subject")

		var (
			policies ladon.Policies
			err      error
		)

		if subject != "" {
			policies, err = guard.Persistence.FindRequestCandidates(&ladon.Request{Subject: subject})
		} else {
			policies, err = guard.Persistence.GetAll(1000, 0)
		}
		if err != nil {
			c.Error(errors.Join(model.ErrInternalServerError, err))
			return
		}

		c.JSON(200, policies)
	})

	router.DELETE(resourceLocation, func(c *gin.Context) {
		ids := []string{}
		if idQuery := c.Query("ids"); idQuery != "" {
			ids = append(ids, strings.Split(idQuery, ",")...)
		}

		var bodyIDs []string
		if err := c.ShouldBindJSON(&bodyIDs); err == nil {
			ids = append(ids, bodyIDs...)
		}

		if len(ids) == 0 {
			c.Error(model.ErrBadRequest)
			return
		}

		for _, id := range ids {
			if id == "admin-all" {
				c.Error(errors.Join(model.ErrBadRequest, errors.New("protected policy")))
				return
			}
			if _, err := guard.Persistence.Get(id); err != nil {
				c.Error(errors.Join(model.ErrNotFound, err))
				return
			}
		}

		for _, id := range ids {
			if err := guard.Persistence.Delete(id); err != nil {
				c.Error(errors.Join(model.ErrInternalServerError, err))
				return
			}
		}

		c.Status(204)
	})

	router.PUT(resourceLocation, func(c *gin.Context) {
		var policies []ladon.DefaultPolicy
		if err := c.ShouldBindJSON(&policies); err != nil {
			c.Error(errors.Join(model.ErrBadRequest, err))
			return
		}

		for _, policy := range policies {
			_, err := guard.Persistence.Get(policy.ID)
			if err != nil {
				err = guard.Persistence.Create(&policy)
			} else {
				err = guard.Persistence.Update(&policy)
			}
			if err != nil {
				c.Error(errors.Join(model.ErrInternalServerError, err))
				return
			}
		}

		c.Status(204)
	})

	router.POST(resourceLocation, func(c *gin.Context) {
		var policies []ladon.DefaultPolicy
		if err := c.ShouldBindJSON(&policies); err != nil {
			c.Error(errors.Join(model.ErrBadRequest, err))
			return
		}

		for _, policy := range policies {
			if _, err := guard.Persistence.Get(policy.GetID()); err == nil {
				c.Error(errors.Join(model.ErrBadRequest, errors.New("policy already exists")))
				return
			}
		}

		for _, policy := range policies {
			if err := guard.Persistence.Create(&policy); err != nil {
				c.Error(errors.Join(model.ErrInternalServerError, err))
				return
			}
		}

		c.Status(204)
	})
}
