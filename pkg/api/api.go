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
	"context"
	"log/slog"
	"net/http"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/SENERGY-Platform/authorization/pkg/api/util"
	"github.com/SENERGY-Platform/authorization/pkg/authorization"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/log"
	"github.com/SENERGY-Platform/authorization/pkg/model"
	gin_mw "github.com/SENERGY-Platform/gin-middleware"
	"github.com/SENERGY-Platform/go-service-base/struct-logger/attributes"
	"github.com/gin-contrib/requestid"
	"github.com/gin-gonic/gin"
)

var endpoints = []func(router *gin.Engine, config configuration.Config, jwt util.Jwt, guard *authorization.Guard){}

func ErrorHandler(f func(error) int, sep string) gin.HandlerFunc {
	return func(gc *gin.Context) {
		gc.Next()
		if !gc.IsAborted() && len(gc.Errors) > 0 {
			var errs []string
			for _, e := range gc.Errors {
				if sc := f(e); sc != 0 {
					gc.Status(sc)
				}
				errs = append(errs, e.Error())
			}
			if gc.Writer.Status() < 400 {
				gc.Status(http.StatusInternalServerError)
			}
			gc.JSON(-1, map[string]any{"errors": errs})
		}
	}
}

// Start godoc
// @title Authorization API
// @description Allows definition of policies and checking of access rights.
// @BasePath /
// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
func Start(ctx context.Context, wg *sync.WaitGroup, config configuration.Config, guard *authorization.Guard) (err error) {
	log.Logger.Info("start api")
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(
		gin_mw.StructLoggerHandlerWithDefaultGenerators(
			log.Logger.With(attributes.LogRecordTypeKey, attributes.HttpAccessLogRecordTypeVal),
			attributes.Provider,
			[]string{},
			nil,
		),
		requestid.New(requestid.WithCustomHeaderStrKey("X-Request-ID")),
		ErrorHandler(model.GetStatusCode, ", "),
		gin_mw.StructRecoveryHandler(log.Logger, gin_mw.DefaultRecoveryFunc),
	)
	jwt := util.NewJwt(config)
	for _, e := range endpoints {
		log.Logger.Info("add endpoint", "name", runtime.FuncForPC(reflect.ValueOf(e).Pointer()).Name())
		e(router, config, jwt, guard)
	}
	server := &http.Server{Addr: ":" + config.ApiPort, Handler: router, WriteTimeout: 10 * time.Second, ReadTimeout: 2 * time.Second, ReadHeaderTimeout: 2 * time.Second}
	wg.Add(1)
	go func() {
		log.Logger.Info("Listening on", slog.String("addr", server.Addr))
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Logger.Error("api server error", attributes.ErrorKey, err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownErr := server.Shutdown(context.Background())
		if shutdownErr != nil {
			log.Logger.Debug("api shutdown", slog.String(attributes.ErrorKey, shutdownErr.Error()))
		} else {
			log.Logger.Debug("api shutdown")
		}
		wg.Done()
	}()
	return nil
}
