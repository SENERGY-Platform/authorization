FROM golang:1.11

WORKDIR /app

COPY ladon.go .

ENV GOPATH ""
ENV GO111MODULE on
RUN go mod init ladon
RUN go get github.com/ory/ladon@v0.8.10
RUN go get github.com/lib/pq
RUN go get github.com/jmoiron/sqlx
RUN go get github.com/rubenv/sql-migrate
RUN go get github.com/ory/pagination

RUN go build

EXPOSE 8080
ENTRYPOINT ["/app/ladon"]