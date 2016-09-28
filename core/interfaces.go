package core

import "github.com/docker/docker/pkg/authorization"

// Authorizer handles the authorization of docker requests and responses
type Authorizer interface {
	// Init initialize the authorizer
	Init() error                                                 // Init initialize the handler
	AuthZReq(req *authorization.Request) *authorization.Response // AuthZReq handles the request from docker client
	// to docker daemon
	AuthZRes(req *authorization.Request) *authorization.Response // AuthZRes handles the response from docker daemon to docker client
}
