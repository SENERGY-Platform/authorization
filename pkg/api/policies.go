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
	router.GET(resourceLocation, policiesGetHandler(guard))
	router.DELETE(resourceLocation, policiesDeleteHandler(guard))
	router.PUT(resourceLocation, policiesPutHandler(guard))
	router.POST(resourceLocation, policiesPostHandler(guard))
}

// policiesGetHandler godoc
// @Summary List policies
// @Description Returns all Ladon policies, optionally filtered by subject.
// @Tags policies
// @Produce json
// @Param subject query string false "Filter policies by subject"
// @Success 200 {array} ladon.DefaultPolicy
// @Failure 500 {string} ErrorResponse
// @Router /policies [get]
func policiesGetHandler(guard *authorization.Guard) gin.HandlerFunc {
	return func(c *gin.Context) {
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
	}
}

// policiesDeleteHandler godoc
// @Summary Delete policies
// @Description Deletes one or more policies by ID. IDs may be provided as a comma-separated query parameter and/or a JSON array in the request body.
// @Tags policies
// @Accept json
// @Param ids query string false "Comma-separated list of policy IDs to delete"
// @Param ids body []string false "List of policy IDs to delete"
// @Success 204
// @Failure 400 {string} ErrorResponse
// @Failure 404 {string} ErrorResponse
// @Failure 500 {string} ErrorResponse
// @Router /policies [delete]
func policiesDeleteHandler(guard *authorization.Guard) gin.HandlerFunc {
	return func(c *gin.Context) {
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
	}
}

// policiesPutHandler godoc
// @Summary Create or update policies
// @Description Creates new policies or updates existing ones. Existing policies are updated; unknown IDs are created.
// @Tags policies
// @Accept json
// @Param policies body []ladon.DefaultPolicy true "List of policies to create or update"
// @Success 204
// @Failure 400 {string} ErrorResponse
// @Failure 500 {string} ErrorResponse
// @Router /policies [put]
func policiesPutHandler(guard *authorization.Guard) gin.HandlerFunc {
	return func(c *gin.Context) {
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
	}
}

// policiesPostHandler godoc
// @Summary Create new policies
// @Description Creates a list of new Ladon policies. Returns an error if any policy ID already exists.
// @Tags policies
// @Accept json
// @Param policies body []ladon.DefaultPolicy true "List of policies to create"
// @Success 204
// @Failure 400 {string} ErrorResponse
// @Failure 500 {string} ErrorResponse
// @Router /policies [post]
func policiesPostHandler(guard *authorization.Guard) gin.HandlerFunc {
	return func(c *gin.Context) {
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
	}
}
