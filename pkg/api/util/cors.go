package util

import "net/http"

func NewCors(handler http.Handler) *CorsMiddleware {
	return &CorsMiddleware{handler: handler}
}

type CorsMiddleware struct {
	handler http.Handler
}

func (this *CorsMiddleware) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	origin := req.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	res.Header().Set("Access-Control-Allow-Origin", origin)
	res.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, authorization, Authorization")
	res.Header().Set("Access-Control-Allow-Credentials", "true")
	res.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")

	if req.Method == "OPTIONS" {
		res.WriteHeader(http.StatusOK)
	} else {
		this.handler.ServeHTTP(res, req)
	}
}
