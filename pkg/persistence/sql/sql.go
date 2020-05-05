package sql

import (
	"context"
	"errors"
	"fmt"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/jmoiron/sqlx"
	"github.com/ory/ladon"
	"log"
	"runtime/debug"
	"sync"
)

import manager "github.com/ory/ladon/manager/sql"

type Persistence struct {
	db    *sqlx.DB
	Ladon *ladon.Ladon
}

func New(ctx context.Context, wg *sync.WaitGroup, config configuration.Config) (result *Persistence, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint("panic during db init: ", r))
			fmt.Println(string(debug.Stack()))
		}
	}()
	// TODO db, err := gorm.Open("mysql", config.SqlConnectionString)
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
	result = &Persistence{db: db, Ladon: warden}
	err = result.migration()
	return result, err
}
