package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/authorization"
	"github.com/docker/docker/pkg/plugins"
	"github.com/gorilla/mux"
)

const (
	pluginName   = "authz-broker"
	pluginFolder = "/run/docker/plugins"
)

//ID2TenantMap - Keep track about resource ownership
var ID2TenantMap map[string]string

//Name2TIDMap - Keep track about resource ownership
var Name2TIDMap map[string]string

// AuthZSrv implements the authz plugin specification on top of unix sockets
// the authZSrv uses two core components to manage the flow, the authorizer,
// which is used to perform the actual authorization.
type AuthZSrv struct {
	authorizer Authorizer   // authorizer is the concrete handler for plugins
	listener   net.Listener // listener is the plugin socket listener
}

// NewAuthZSrv creates a new authorization server
func NewAuthZSrv(plugin Authorizer) *AuthZSrv {
	return &AuthZSrv{authorizer: plugin}
}

// Start starts the authorization server
func (a *AuthZSrv) Start() error {
	err := a.authorizer.Init()

	if err != nil {
		return err
	}

	if _, err := os.Stat(pluginFolder); os.IsNotExist(err) {
		logrus.Infof("Creating plugins folder %q", pluginName)
		err = os.MkdirAll("/run/docker/plugins/", 0750)
		if err != nil {
			return err
		}
	}

	pluginPath := fmt.Sprintf("%s/%s.sock", pluginFolder, pluginName)

	os.Remove(pluginPath)
	a.listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: pluginPath, Net: "unix"})
	if err != nil {
		return err
	}
	router := mux.NewRouter()
	router.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		b, err := json.Marshal(plugins.Manifest{Implements: []string{authorization.AuthZApiImplements}})

		if err != nil {
			writeErr(w, err)
			return
		}

		w.Write(b)
	})

	router.HandleFunc(fmt.Sprintf("/%s", authorization.AuthZApiRequest), func(w http.ResponseWriter, r *http.Request) {

		defer r.Body.Close()
		body, err := ioutil.ReadAll(r.Body)

		if err != nil {
			writeErr(w, err)
			return
		}

		var authReq authorization.Request
		err = json.Unmarshal(body, &authReq)

		if err != nil {
			writeErr(w, err)
			return
		}

		authZRes := a.authorizer.AuthZReq(&authReq)

		if authZRes != nil {
			logrus.Debugf(authZRes.Msg)
		}

		writeResponse(w, authZRes)
	})

	router.HandleFunc(fmt.Sprintf("/%s", authorization.AuthZApiResponse), func(w http.ResponseWriter, r *http.Request) {

		defer r.Body.Close()
		body, err := ioutil.ReadAll(r.Body)

		if err != nil {
			writeErr(w, err)
			return
		}

		var authReq authorization.Request
		err = json.Unmarshal(body, &authReq)

		if err != nil {
			writeErr(w, err)
			return
		}

		authZRes := a.authorizer.AuthZRes(&authReq)

		writeResponse(w, authZRes)
	})
	ID2TenantMap = make(map[string]string)
	Name2TIDMap = make(map[string]string)
	logrus.Info("Initialized authorization server")
	return http.Serve(a.listener, router)
}

// Stop stops the authorization server
func (a *AuthZSrv) Stop() {

	if a.listener == nil {
		logrus.Warnf("Listener is nil")
		return
	}
	a.listener.Close()
}

// writeResponse writes the authZPlugin response to response writer
func writeResponse(w http.ResponseWriter, authZRes *authorization.Response) {

	data, err := json.Marshal(authZRes)
	if err != nil {
		logrus.Errorf("Failed to marshel authz response %q", err.Error())
	} else {
		w.Write(data)
	}

	if authZRes == nil || authZRes.Err != "" {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// writeErr writes the authZPlugin error response to response writer
func writeErr(w http.ResponseWriter, err error) {
	writeResponse(w, &authorization.Response{Err: err.Error()})
}