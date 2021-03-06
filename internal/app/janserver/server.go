package janserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/JohnNON/goJAN/internal/app/model"
	"github.com/JohnNON/goJAN/internal/app/store"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
)

type ctxKey int8

type server struct {
	router       *mux.Router
	logger       *logrus.Logger
	store        store.Store
	sessionStore sessions.Store
	csrfSecurity mux.MiddlewareFunc
}

const (
	sessionName        = "janserverUser"
	ctxKeyUser  ctxKey = iota
	ctxKeyRequestID
	ctxKeyMessage
)

var (
	errIncorrectEmailOrPassword = errors.New("incorect email or password")
	errNotAuthenticated         = errors.New("not authenticated")
	errInternalServerError      = errors.New("internal server error")
)

func newServer(store store.Store, sessionStore sessions.Store, csrf mux.MiddlewareFunc) *server {
	s := &server{
		router:       mux.NewRouter(),
		logger:       logrus.New(),
		store:        store,
		sessionStore: sessionStore,
		csrfSecurity: csrf,
	}

	s.configureRouter()

	return s
}

// ServeHTTP - выполняет обслуживание запросов, делегируя их router
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) configureRouter() {
	s.router.Use(s.setRequestID)
	s.router.Use(s.logRequest)
	s.router.Use(handlers.CORS(handlers.AllowedOrigins([]string{"*"})))
	s.router.Use(s.csrfSecurity)
	s.router.HandleFunc("/", s.handleLogin()).Methods("GET")
	s.router.HandleFunc("/index", s.handleLogin()).Methods("GET")
	s.router.HandleFunc("/login", s.handleLogin()).Methods("POST", "GET")
	s.router.HandleFunc("/logout", s.handleLogout()).Methods("GET")
	s.router.HandleFunc("/registration", s.handleRegistration()).Methods("POST", "GET")
	s.router.PathPrefix("/assets").Handler(http.StripPrefix("/assets/static/", http.FileServer(http.Dir("./internal/static/"))))

	private := s.router.PathPrefix("/private").Subrouter()
	private.Use(s.authenticateUser)
	private.HandleFunc("/whoami", s.handleWhoami()).Methods("GET")

}

func (s *server) handleWhoami() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.response(w, r, http.StatusOK, r.Context().Value(ctxKeyUser).(*model.User))
	}
}

func (s *server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.response(w, r, code, map[string]string{"error": err.Error()})
}

func (s *server) response(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func (s *server) authenticateUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionStore.Get(r, sessionName)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		id, ok := session.Values["user_id"]
		if !ok || id == nil {
			//s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		u, err := s.store.User().Find(id.(int))
		if err != nil {
			//s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser, u)))
	})
}

func (s *server) setRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, id)))
	})
}

func (s *server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger.WithFields(logrus.Fields{
			"remote_addr": r.RemoteAddr,
			"request_id":  r.Context().Value(ctxKeyRequestID),
		})
		logger.Infof("started %s=%s", r.Method, r.RequestURI)

		start := time.Now()

		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)

		logger.Infof(
			"complited with %d - %s in %v",
			rw.code,
			http.StatusText(rw.code),
			time.Now().Sub(start),
		)
	})
}
