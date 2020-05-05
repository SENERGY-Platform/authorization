package util

import (
	"errors"
	"fmt"
	"github.com/SENERGY-Platform/authorization/pkg/configuration"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"strings"
)

type Jwt struct {
	config configuration.Config
}

func NewJwt(config configuration.Config) Jwt {
	return Jwt{config: config}
}

const PEM_BEGIN = "-----BEGIN PUBLIC KEY-----"
const PEM_END = "-----END PUBLIC KEY-----"

func (this Jwt) Parse(token string) (username string, user string, roles []string, err error) {
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		switch this.config.JwtSigningMethod {
		case "rsa":
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			key := this.config.JwtSigningKey
			if !strings.HasPrefix(key, PEM_BEGIN) {
				key = PEM_BEGIN + "\n" + key + "\n" + PEM_END
			}
			return jwt.ParseRSAPublicKeyFromPEM([]byte(key))
		case "hmac":
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(this.config.JwtSigningKey), nil
		}
		return "", nil
	})

	if err != nil {
		if this.config.Debug {
			log.Println("DEBUG: unable to parse jwt: ", err)
		}
		err = errors.New("unable to parse jwt")
		return username, user, roles, err
	}

	if !jwtToken.Valid {
		return username, user, roles, errors.New("invalid jwt")
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return username, user, roles, errors.New("missing jwt claims")
	}
	user, ok = claims["sub"].(string)
	if !ok {
		return username, user, roles, errors.New("missing jwt sub")
	}
	username, ok = claims["preferred_username"].(string)
	if !ok {
		return username, user, roles, errors.New("missing jwt realm_access.preferred_username")
	}
	realmAccess, ok := claims["realm_access"].(map[string]interface{})
	if !ok {
		return username, user, roles, errors.New("missing jwt realm_access")
	}
	realmRoles, ok := realmAccess["roles"].([]interface{})
	if !ok {
		return username, user, roles, errors.New("missing jwt realm_access.roles")
	}
	for _, role := range realmRoles {
		roleName, ok := role.(string)
		if !ok {
			return username, user, roles, errors.New("jwt realm_access.roles enty is not string")
		}
		roles = append(roles, roleName)
	}
	return
}

func (this Jwt) ParseRequest(request *http.Request) (username string, user string, roles []string, err error) {
	auth := request.Header.Get("Authorization")
	if auth == "" {
		err = errors.New("missing Authorization header")
	}
	authParts := strings.Split(auth, " ")
	if len(authParts) != 2 {
		return username, user, roles, errors.New("expect auth string format like '<type> <token>'")
	}
	return this.Parse(strings.Join(authParts[1:], " "))
}
