package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/idena-network/idena-auth/core"
	"github.com/idena-network/idena-auth/types"
	log "github.com/inconshreveable/log15"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
)

type Server struct {
	port       int
	auth       core.Auth
	mutex      sync.Mutex
	counter    int
	httpServer *http.Server
}

func NewServer(port int, auth core.Auth) *Server {
	return &Server{
		port: port,
		auth: auth,
	}
}

func (s *Server) Start() {
	router := mux.NewRouter().PathPrefix("/{version}").Subrouter()
	s.initRouter(router)
	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})
	addr := fmt.Sprintf(":%d", s.port)
	handler := handlers.CORS(originsOk, headersOk, methodsOk)(s.requestFilter(router))
	httpServer := &http.Server{Addr: addr, Handler: handler}
	s.httpServer = httpServer
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}

func (s *Server) Stop() {
	if s.httpServer == nil {
		return
	}
	if err := s.httpServer.Shutdown(context.Background()); err != nil {
		panic(err)
	}
}

func (s *Server) requestFilter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqId := s.generateReqId()
		log.Debug(fmt.Sprintf("Got request %v, url: %v, from: %v", reqId, r.URL, GetIP(r)))
		defer log.Debug(fmt.Sprintf("Completed request %v", reqId))
		err := r.ParseForm()
		if err != nil {
			log.Error(fmt.Sprintf("Unable to parse request %v: %v", reqId, err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.URL.Path = strings.ToLower(r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) generateReqId() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	id := s.counter
	s.counter++
	return id
}

func GetIP(r *http.Request) string {
	header := r.Header.Get("X-Forwarded-For")
	if len(header) > 0 {
		return strings.Split(header, ", ")[0]
	}
	if strings.Contains(r.RemoteAddr, ":") {
		return strings.Split(r.RemoteAddr, ":")[0]
	}
	return r.RemoteAddr
}

func (s *Server) initRouter(router *mux.Router) {
	router.Path(strings.ToLower("/start-session")).HandlerFunc(s.startSession).Methods("POST")
	router.Path(strings.ToLower("/authenticate")).HandlerFunc(s.authenticate).Methods("POST")
	router.Path(strings.ToLower("/get-account")).
		Queries("token", "{token}").HandlerFunc(s.getAccount).Methods("GET")
	router.Path(strings.ToLower("/logout")).HandlerFunc(s.logout).Methods("POST")
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		writeResponse(w, nil, err)
		return
	}
	request := types.StartSessionRequest{}
	err = json.Unmarshal(body, &request)
	if err != nil {
		writeResponse(w, nil, err)
		return
	}
	resp, err := s.auth.StartSession(mux.Vars(r)["version"], request)
	writeResponse(w, resp, err)
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		writeResponse(w, nil, err)
		return
	}
	request := types.AuthenticateRequest{}
	err = json.Unmarshal(body, &request)
	if err != nil {
		writeResponse(w, nil, err)
		return
	}
	resp, err := s.auth.Authenticate(mux.Vars(r)["version"], request)
	writeResponse(w, resp, err)
}

func (s *Server) getAccount(w http.ResponseWriter, r *http.Request) {
	resp, err := s.auth.GetAccount(mux.Vars(r)["version"], mux.Vars(r)["token"])
	writeResponse(w, resp, err)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	fmt.Println(fmt.Sprintf("logout req: |%v|", string(body)))
	if err != nil {
		writeResponse(w, nil, err)
		return
	}
	request := types.LogoutRequest{}
	err = json.Unmarshal(body, &request)
	if err != nil {
		writeResponse(w, nil, err)
		return
	}
	resp, err := s.auth.Logout(mux.Vars(r)["version"], request)
	writeResponse(w, resp, err)
}

func writeResponse(w http.ResponseWriter, result interface{}, err error) {
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(getResponse(result, err))
	if err != nil {
		log.Error(fmt.Sprintf("Unable to write response: %v", err))
		return
	}
}

func getResponse(result interface{}, err error) types.Response {
	if err != nil {
		return getErrorResponse(err)
	}
	return types.Response{
		Success: true,
		Data:    result,
	}
}

func getErrorResponse(err error) types.Response {
	return getErrorMsgResponse(err.Error())
}

func getErrorMsgResponse(errMsg string) types.Response {
	return types.Response{
		Error: errMsg,
	}
}
