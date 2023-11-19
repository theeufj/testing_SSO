package middleware

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"testingSSO/api"
)

// Reference: https://golang.org/pkg/context/#WithValue
type ctxKey struct{}

func NoCaching(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=0, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

func WebLoggings(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.RequestURI, "via", r.Referer())
		next.ServeHTTP(w, r)
	})
}

func RequireValidCookieJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("secureCookie")
		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				http.Redirect(w, r, fmt.Sprintf("/login?destination=%s", url.QueryEscape(r.URL.Path)), http.StatusSeeOther)
			default:
				log.Println(err)
				http.Error(w, "server error", http.StatusInternalServerError)
			}
			return
		}

		reqToken := cookie.Value
		// Decode token into JWT?
		vals, err := api.DecodeJWTToUser(reqToken)
		if err != nil {
			log.Println("Error", err)
			http.Redirect(w, r, fmt.Sprintf("/login?destination=%s", url.QueryEscape(r.URL.Path)), http.StatusSeeOther)
			return
		}

		// TODO: Refresh the cookie here

		ctx := context.WithValue(r.Context(), ctxKey{}, Session{
			Hello: vals.Get("Name"),
		})

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func JSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func CSRFToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// TODO check for X-Csrf-Token
		if ua := r.Header.Get("X-Csrf-Token"); ua != "" {
			next.ServeHTTP(w, r)
			return
		}
		api.JSONError(w, http.StatusUnauthorized, "X-Csrf-Token not found")
	})
}

type Session struct {
	Hello string
}

func SessionFromCtx(req *http.Request) (Session, bool) {
	session, ok := req.Context().Value(ctxKey{}).(Session)
	if session == (Session{}) {
		return Session{}, ok
	}
	return session, ok
}

// TODO
// https://en.wikipedia.org/wiki/Cross-site_request_forgery?ref=jerrynsh.com#Cookie-to-header_token
func RequireValidJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Break up the bearer
		prefix := "Bearer "
		authHeader := r.Header.Get("Authorization")
		reqToken := strings.TrimPrefix(authHeader, prefix)

		log.Println(reqToken)

		if authHeader == "" || reqToken == authHeader {
			api.JSONError(w, http.StatusUnauthorized, "Authentication header not present or malformed")
			return
		}

		// Decode token into JWT?
		str, err := api.DecodeJWTToUser(reqToken)
		if err != nil {
			api.JSONError(w, http.StatusUnauthorized, err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), ctxKey{}, Session{
			Hello: str.Get("Name"),
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
