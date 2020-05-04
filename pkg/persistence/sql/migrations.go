package sql

import (
	"github.com/ory/ladon"
	"log"
)

func (this *Persistence) migration() (err error) {
	// Create admin policy
	var pol = &ladon.DefaultPolicy{
		ID:          "admin-all",
		Description: "init policy for role admin",
		Subjects:    []string{"admin"},
		Resources:   []string{"<.*>"},
		Actions:     []string{"POST", "GET", "DELETE", "PATCH", "PUT", "HEAD"},
		Effect:      ladon.AllowAccess,
	}
	err = this.ladon.Manager.Create(pol)
	if err != nil {
		log.Fatal("Created inital policy: ", err)
		return err
	}

	return err
}
