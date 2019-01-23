FROM golang:1.9

COPY ladon.go /ladon.go
RUN go get github.com/ory/ladon
RUN go get github.com/lib/pq
RUN go get github.com/jmoiron/sqlx
RUN go get github.com/rubenv/sql-migrate
RUN go get github.com/ory/pagination

WORKDIR /

EXPOSE 8080

CMD go run ./ladon.go