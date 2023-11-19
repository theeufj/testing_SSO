package main

import (
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"testingSSO/api"
	"testingSSO/env"
	"testingSSO/middleware"

	"github.com/gorilla/mux"
)

var (
	logger *slog.Logger
)

var index = template.Must(template.ParseFiles("templates/layout.tmpl.html", "templates/index.tmpl.html"))
var login = template.Must((template.ParseFiles("templates/login.tmpl.html")))

func main() {
	port := env.GetAsString("PORT", "8080")
	appEnv := env.GetAsString("ENV", "dev")

	opts := &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug, // we should toggle this if we're in prod
	}

	var handler slog.Handler = slog.NewTextHandler(os.Stdout, opts)
	if appEnv == "production" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	logger = slog.New(handler)
	slog.SetDefault(logger) // Set the default logger

	logger.Info("Starting server...", "server", fmt.Sprintf("http://localhost:%s", port))

	r := mux.NewRouter()
	protectedAPIRouter := r.PathPrefix("/api/").Subrouter()
	protectedWebRouter := r.PathPrefix("").Subrouter()
	unprotectedRouter := r.PathPrefix("/").Subrouter()

	protectedAPIRouter.Use(
		middleware.JSON,
		middleware.NoCaching,
		middleware.RequireValidJWT,
	)

	protectedWebRouter.Use(
		middleware.WebLoggings,
		middleware.RequireValidCookieJWT,
		middleware.NoCaching,
	)

	unprotectedRouter.Use(
		middleware.WebLoggings,
	)
	unprotectedRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		index.Execute(w, nil)
	})

	unprotectedRouter.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		f := struct{ Error bool }{false}
		switch r.Method {
		case http.MethodGet:
			// Sure, let them login again
		case http.MethodPost:
			username := r.FormValue("email")
			// write logic for handlling login

			if username != "admin" {
				f.Error = true
				break
			}
			vars := api.JWTValues{}
			vars.Set("Name", "Secured")
			toke := api.CreateJWTTokenForUser(vars)
			cookie := http.Cookie{
				Name:     "secureCookie",
				Value:    toke,
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(w, &cookie)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			log.Println("Logging in...")
			return
		}
		login.Execute(w, f)
	})

	// Setup filehandling
	fs := http.FileServer(http.Dir("./static"))
	unprotectedRouter.PathPrefix("/static").Handler(http.StripPrefix("/static", fs))

	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, r))
}
