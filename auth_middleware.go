package cerbero

import (
	"context"
	"net/http"
)

type key int

var userKey key = 0

const BearerLength = 7

type Authenticator struct {
	mutationClient MutationClient
	Restricted     bool
}

func NewAuthenticator(mutationClient MutationClient) *Authenticator {
	return &Authenticator{
		mutationClient: mutationClient,
		Restricted:     true,
	}
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !(len(authHeader) > BearerLength) {
			if a.Restricted {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				next.ServeHTTP(w, r)
			}
			return
		}
		token := authHeader[BearerLength:]
		req := &AuthenticateRequest{
			Token: token,
		}
		ctx := r.Context()
		user, err := a.mutationClient.Authenticate(ctx, req)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx = setUser(ctx, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetUser(ctx context.Context) *UserSession {
	user, ok := ctx.Value(userKey).(*UserSession)
	if !ok {
		return nil
	}
	return user
}

func MockUser(ctx context.Context, user *UserSession) context.Context {
	return setUser(ctx, user)
}

func setUser(ctx context.Context, user *UserSession) context.Context {
	return context.WithValue(ctx, userKey, user)
}
