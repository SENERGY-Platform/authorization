package api

import (
	"encoding/json"
	"github.com/SENERGY-Platform/authorization/pkg/api/util"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/persistence/sql"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/ladon"
	"log"
	"net/http"
	"runtime/debug"
)

type ResponseMessage struct {
	Result string "json:result"
	Error  string "json:error"
}

type PolicyMessage struct {
	Policy string "json:policy"
}

type KongMessage struct {
	Result bool   "json:result"
	Error  string "json:error"
}

func init() {
	endpoints = append(endpoints, PoliciesEndpoints)
}

func PoliciesEndpoints(router *httprouter.Router, config configuration.Config, jwt util.Jwt, persistence *sql.Persistence) {

	router.GET("/bricks/:id", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

	})

	router.DELETE("/bricks/:id", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

	})

	router.PUT("/bricks/:id", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

	})

	router.POST("/policies", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		decoder := json.NewDecoder(request.Body)
		pol := new(ladon.DefaultPolicy)
		err := decoder.Decode(&pol)
		writer.Header().Set("Content-Type", "application/json")
		var message ResponseMessage
		if err != nil {
			http.Error(writer, "Could not parse policy", http.StatusBadRequest)
			return
		}

		if err := persistence.Ladon.Manager.Create(pol); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		message = ResponseMessage{
			"policy created successfully",
			"",
		}
		err = json.NewEncoder(writer).Encode(message)
		if err != nil {
			log.Println("ERROR:", err)
			debug.PrintStack()
		}
	})

	router.GET("/bricks", func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

	})

}
