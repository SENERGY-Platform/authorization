module github.com/SENERGY-Platform/authorization

go 1.16

require (
	github.com/golang-jwt/jwt v3.2.1+incompatible
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/jmoiron/sqlx v1.2.0
	github.com/julienschmidt/httprouter v1.3.0
	github.com/lib/pq v1.5.0
	github.com/ory/dockertest v3.3.5+incompatible // indirect
	github.com/ory/dockertest/v3 v3.9.1 // indirect
	github.com/ory/ladon v0.8.10
	github.com/ory/pagination v0.0.1 // indirect
	github.com/rubenv/sql-migrate v0.0.0-20200429072036-ae26b214fa43 // indirect
)

replace github.com/ory/dockertest v3.3.5+incompatible => github.com/ory/dockertest/v3 v3.7.0
