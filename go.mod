module github.com/SENERGY-Platform/authorization

go 1.16

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/containerd/continuity v0.0.0-20200413184840-d3ef23f19fbb // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/golang-jwt/jwt v3.2.1+incompatible
	github.com/gotestyourself/gotestyourself v2.2.0+incompatible // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/jmoiron/sqlx v1.2.0
	github.com/julienschmidt/httprouter v1.3.0
	github.com/lib/pq v1.5.0
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/ory/dockertest v3.3.5+incompatible // indirect
	github.com/ory/ladon v0.8.10
	github.com/ory/pagination v0.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rubenv/sql-migrate v0.0.0-20200429072036-ae26b214fa43 // indirect
	github.com/stretchr/testify v1.5.1 // indirect
	gotest.tools v2.2.0+incompatible // indirect
)

replace (
	github.com/ory/dockertest v3.3.5+incompatible => github.com/ory/dockertest/v3 v3.7.0
)