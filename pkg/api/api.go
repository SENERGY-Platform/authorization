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
	"github.com/SENERGY-Platform/go-service-base/struct-logger/attributes"
	"github.com/SENERGY-Platform/service-commons/pkg/accesslog"
	"github.com/julienschmidt/httprouter"
)

var endpoints = []func(router *httprouter.Router, config configuration.Config, jwt util.Jwt, guard *authorization.Guard){}

// starts http server; if wg is not nil it will be set as done when the server is stopped
func Start(ctx context.Context, wg *sync.WaitGroup, config configuration.Config, guard *authorization.Guard) (err error) {
	log.Logger.Info("start api")
	router := Router(config, guard)
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

func Router(config configuration.Config, guard *authorization.Guard) http.Handler {
	jwt := util.NewJwt(config)
	router := httprouter.New()
	for _, e := range endpoints {
		log.Logger.Info("add endpoints", slog.String("endpoint", runtime.FuncForPC(reflect.ValueOf(e).Pointer()).Name()))
		e(router, config, jwt, guard)
	}
	log.Logger.Info("add logging and cors")
	return accesslog.New(util.NewCors(router))
}
