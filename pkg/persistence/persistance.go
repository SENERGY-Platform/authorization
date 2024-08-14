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

package persistence

import (
	"context"
	"errors"
	"fmt"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/persistence/memcache"
	"github.com/jmoiron/sqlx"
	"github.com/ory/ladon"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

import _ "github.com/lib/pq"

import manager "github.com/ory/ladon/manager/sql"

type Persistence struct {
	db              *sqlx.DB
	ladon           *ladon.Ladon
	mc              *memcache.Memcache
	debounceMcError *time.Time
}

func New(ctx context.Context, wg *sync.WaitGroup, config configuration.Config) (result *Persistence, err error) {
	mc, err := memcache.New(config.MemcachedUrls)
	if err != nil {
		return nil, err
	}

	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint("panic during db init: ", r))
			fmt.Println(string(debug.Stack()))
		}
	}()
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", config.PostgresHost, 5432, config.PostgresUser, config.PostgresPassword, config.PostgresDb)

	db, err := sqlx.Open("postgres", psqlInfo)
	if err != nil {
		fmt.Println("error")
		log.Fatalf("Could not connect to database: %s", err)
	}

	warden := &ladon.Ladon{
		Manager: manager.NewSQLManager(db, nil),
	}

	if config.Debug {
		warden.AuditLogger = &ladon.AuditLoggerInfo{}
	}

	s := manager.NewSQLManager(db, nil)
	_, err = s.CreateSchemas("", "")
	if err != nil {
		log.Fatalf("Could not create postgres schema: %v", err)
		return result, err
	}
	wg.Add(1)
	go func() {
		<-ctx.Done()
		err = db.Close()
		if err != nil {
			log.Fatalf("Could not close DB connection: %v", err)
		}
		wg.Done()
	}()

	result = &Persistence{db: db, ladon: warden, mc: mc}
	err = result.migration()
	return result, err
}
