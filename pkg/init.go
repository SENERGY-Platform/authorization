package pkg

import (
	"context"
	"github.com/SENERGY-Platform/authorization/pkg/api"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/SENERGY-Platform/authorization/pkg/persistence/sql"
	"sync"
)

//starts services and goroutines; returns a waiting group which is done as soon as all go routines are stopped
func Start(ctx context.Context, config configuration.Config) (wg *sync.WaitGroup, err error) {
	wg = &sync.WaitGroup{}
	db, err := sql.New(ctx, wg, config)
	if err != nil {
		return wg, err
	}
	if err != nil {
		return wg, err
	}
	err = api.Start(ctx, wg, config, db)
	return
}
