/*
 *    Copyright 2026 InfAI (CC SES)
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
	"slices"

	"github.com/SENERGY-Platform/authorization/pkg/api/util"
	"github.com/SENERGY-Platform/authorization/pkg/log"
	"github.com/SENERGY-Platform/authorization/pkg/model"
	"github.com/gin-gonic/gin"
)

const adminRole = "admin"

// requireAdmin runs next only for a request whose Authorization header carries a valid JWT with the realm role admin.
// It wraps the handler instead of being a chained middleware because ErrorHandler writes no response for an aborted context.
func requireAdmin(jwt util.Jwt, next gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		username, userId, roles, clientId, err := jwt.ParseHeader(header)
		if err != nil {
			scheme, sub, exp := util.DescribeHeader(header)
			log.Logger.Warn("Admin authentication failed (401)",
				"authScheme", scheme,
				"sub", sub,
				"exp", exp,
				"method", c.Request.Method,
				"path", c.FullPath(),
			)
			c.Error(errors.Join(model.GetError(401), err))
			return
		}
		if !slices.Contains(roles, adminRole) {
			log.Logger.Warn("Admin authorization failed (403)",
				"userId", userId,
				"username", username,
				"clientId", clientId,
				"method", c.Request.Method,
				"path", c.FullPath(),
			)
			c.Error(errors.Join(model.GetError(403), errors.New("admin role required")))
			return
		}
		next(c)
	}
}
