/*
 *    Copyright 2018 InfAI (CC SES)
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

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/SENERGY-Platform/authorization/pkg"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/ory/ladon"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

import _ "github.com/lib/pq"

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

func policies(w http.ResponseWriter, r *http.Request, manager *ladon.Manager) {
	if r.Method == "POST" {
		decoder := json.NewDecoder(r.Body)
		pol := new(ladon.DefaultPolicy)
		err := decoder.Decode(&pol)
		w.Header().Set("Content-Type", "application/json")
		var message ResponseMessage
		if err != nil {
			message = ResponseMessage{
				"parsing was not successfully",
				err.Error(),
			}
			json_message, _ := json.Marshal(message)
			w.WriteHeader(400)
			fmt.Fprintf(w, string(json_message))
			return
		}
		defer r.Body.Close()

		if err := (*manager).Create(pol); err != nil {
			message = ResponseMessage{
				"policy not created successfully",
				err.Error(),
			}
			w.WriteHeader(500)

		} else {
			message = ResponseMessage{
				"policy created successfully",
				"",
			}
		}
		json_message, _ := json.Marshal(message)
		fmt.Fprintf(w, string(json_message))
	} else if r.Method == "GET" {
		subject := r.URL.Query()["subject"]
		if len(subject) != 0 {
			request := &ladon.Request{
				Subject: subject[0],
			}

			// filter for policies that matches the request
			if policies, err := (*manager).FindRequestCandidates(request); err != nil {
				var message ResponseMessage
				message = ResponseMessage{
					"error at finding policies to the subject",
					err.Error(),
				}
				json_message, _ := json.Marshal(message)
				w.WriteHeader(500)
				fmt.Fprintf(w, string(json_message))
			} else {
				json_message, _ := json.Marshal(policies)
				fmt.Fprintf(w, string(json_message))
			}
		} else {
			if policies, err := (*manager).GetAll(1000, 0); err != nil {
				var message ResponseMessage
				message = ResponseMessage{
					"error at getting all policies",
					err.Error(),
				}
				json_message, _ := json.Marshal(message)
				w.WriteHeader(500)
				fmt.Fprintf(w, string(json_message))
			} else {
				json_message, _ := json.Marshal(policies)
				fmt.Fprintf(w, string(json_message))
			}
		}

	} else if r.Method == "DELETE" {
		id := r.URL.Query()["id"]
		if len(id) != 0 {
			if id[0] == "admin-all" {
				var message ResponseMessage
				message = ResponseMessage{
					"Did not delete policy",
					"Will not delete policy admin-all: protected policy",
				}
				json_message, _ := json.Marshal(message)
				w.WriteHeader(401)
				fmt.Fprintf(w, string(json_message))
				return
			}
			log.Printf("Delete policy with id")
			if err := (*manager).Delete(id[0]); err != nil {
				var message ResponseMessage
				message = ResponseMessage{
					"error at deleting policy",
					err.Error(),
				}
				json_message, _ := json.Marshal(message)
				w.WriteHeader(500)
				fmt.Fprintf(w, string(json_message))
			} else {
				var message ResponseMessage
				message = ResponseMessage{
					"successfully deleted policy",
					"",
				}
				json_message, _ := json.Marshal(message)
				fmt.Fprintf(w, string(json_message))
			}
		} else {
			var message ResponseMessage
			message = ResponseMessage{
				"expected policy id",
				"",
			}
			json_message, _ := json.Marshal(message)
			w.WriteHeader(400)
			fmt.Fprintf(w, string(json_message))
			return
		}
	}
	// go <-> js pytoh scope re assign in if blog -> declare outside ist gleich, aber bei go wird duchr := und = assignt wodrch nicht mehr sichtbar
}

func access(w http.ResponseWriter, r *http.Request, warden ladon.Warden, manager *ladon.Manager) {
	decoder := json.NewDecoder(r.Body)
	request := new(ladon.Request)
	err := decoder.Decode(&request)
	w.Header().Set("Content-Type", "application/json")

	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "Error at parsing JSON")
		return
	}
	defer r.Body.Close()

	request_formatted, _ := json.Marshal(request)
	fmt.Println("Check request: " + string(request_formatted))

	var message KongMessage
	if err := warden.IsAllowed(request); err != nil {
		message = KongMessage{
			false,
			err.Error(),
		}
		w.WriteHeader(500)
	} else {
		message = KongMessage{
			true,
			"",
		}
	}

	json_message, _ := json.Marshal(message)
	fmt.Println("Result of access request: " + string(json_message))
	fmt.Fprintf(w, string(json_message))
}

func main() {

	configLocation := flag.String("config", "config.json", "configuration file")
	flag.Parse()

	config, err := configuration.Load(*configLocation)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	wg, err := pkg.Start(ctx, config)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		shutdown := make(chan os.Signal, 1)
		signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
		sig := <-shutdown
		log.Println("received shutdown signal", sig)
		cancel()
	}()

	wg.Wait()
	// TODO TRASH BELOW

	http.HandleFunc("/policies", func(w http.ResponseWriter, r *http.Request) {
		policies(w, r, &warden.Manager)
	})

	http.HandleFunc("/access", func(w http.ResponseWriter, r *http.Request) {
		access(w, r, warden, &warden.Manager)
	})

	//logger := NewLogger(http.DefaultServeMux, "DEBUG")
	err_start_server := http.ListenAndServe(":8080", nil) // set listen port

	if err_start_server != nil {
		log.Fatal("ListenAndServe: ", err_start_server)
	}

}