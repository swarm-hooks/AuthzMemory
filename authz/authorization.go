package authz

import (
	"encoding/json"
	"io"
	"strconv"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/pkg/authorization"
	"github.com/AuthzMemory/core"

	//	"fmt"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	"golang.org/x/net/context"
)

const (

	// AuditHookStdout indicates logs are streamed to stdout
	AuditHookStdout = ""
)

// defaultAuditLogPath is the file test hook log path
const defaultAuditLogPath = "/var/log/authz-broker.log"

type basicAuthorizer struct {
	settings *BasicAuthorizerSettings
}

// BasicAuthorizerSettings provides settings for the basic authoerizer flow
type BasicAuthorizerSettings struct {
}

var memoryLimit int64
var currentMemory float64
var cli *client.Client

// NewBasicAuthZAuthorizer creates a new basic authorizer
func NewBasicAuthZAuthorizer(settings *BasicAuthorizerSettings) core.Authorizer {
	return &basicAuthorizer{settings: settings}
}

// Init loads the basic authz plugin configuration from disk
func (f *basicAuthorizer) Init() error {
	currentMemory = 0.0
	memoryLimit = 0
	return nil
}

func initializeOnFirstCall() error {
	defaultHeaders := map[string]string{"User-Agent": "engine-api-cli-1.0", AuthZTenantIDHeaderName: "infoTenantInternal"}
	var err error
	cli, err = client.NewClient("unix:///var/run/docker.sock", "v1.24", nil, defaultHeaders)
	if err != nil {
		panic(err)
	}

	info, err := cli.Info(context.Background())
	memoryLimit = info.MemTotal

	if err != nil {
		panic(err)
	}

	type decodingResult struct {
		msg events.Message
		err error
	}

	//TODO - Fix this it only takes one event

	stopChan := make(chan struct{})
	responseBody, err := cli.Events(context.Background(), types.EventsOptions{})
	if err != nil {
		panic(err)
	}
	resultChan := make(chan decodingResult)

	go func() {
		dec := json.NewDecoder(responseBody)
		for {
			var result decodingResult
			result.err = dec.Decode(&result.msg)
			resultChan <- result
			if result.err == io.EOF {
				break
			}
		}
		close(resultChan)
	}()

	go func() {
		defer responseBody.Close()
		for {
			select {
			case <-stopChan:
				// ec <- nil
				return
			case result := <-resultChan:
				if result.err != nil {
					// ec <- result.err
					return
				}
				logrus.Info(result.msg)
			}
		}
	}()

	go func() {
		for {

			options := types.ContainerListOptions{All: true}
			containers, err := cli.ContainerList(context.Background(), options)
			if err != nil {
				panic(err)
			}
			var tmp int64
			for _, c := range containers {
				cJSON, _ := cli.ContainerInspect(context.Background(), c.ID)

				if cJSON.ContainerJSONBase != nil && cJSON.ContainerJSONBase.HostConfig != nil {
					tmp += cJSON.ContainerJSONBase.HostConfig.Memory
					if cJSON.ContainerJSONBase.HostConfig.Memory == 0 {
						logrus.Infof("Warning no memory accounted for container %s ", cJSON.ID)
					}
				}

			}
			logrus.Info("Current memory used: " + strconv.FormatInt(int64(tmp), 10))
			currentMemory = float64(tmp)
			time.Sleep(120 * time.Second)
		}
	}()
	return nil
}

//AuthZTenantIDHeaderName - TenantId HTPP header name.
var AuthZTenantIDHeaderName = "X-Auth-Tenantid"

func (f *basicAuthorizer) AuthZReq(authZReq *authorization.Request) *authorization.Response {
	if memoryLimit == 0 {
		memoryLimit = 1 //Prevent infitine loop of querinying this plugin
		initializeOnFirstCall()
	}
	// logrus.Infof("Received AuthZ request, method: '%s', url: '%s' , headers: '%s'", authZReq.RequestMethod, authZReq.RequestURI, authZReq.RequestHeaders)

	action, _ := core.ParseRoute(authZReq.RequestMethod, authZReq.RequestURI)

	if action == core.ActionContainerCreate {
		var request interface{}
		err := json.Unmarshal(authZReq.RequestBody, &request)
		if err != nil {
			logrus.Error(err)
		}
		m := request.(map[string]interface{})
		// logrus.Info(m)
		hostConfig := m["HostConfig"].(map[string]interface{})

		memory := hostConfig["Memory"].(float64)
		if memory == 0.0 {
			return &authorization.Response{
				Allow: false,
				Msg:   "Must request Memory",
			}
		}
		// logrus.Info(memory)
		if float64(currentMemory)+memory < float64(memoryLimit) {
			currentMemory += memory
			return &authorization.Response{
				Allow: true,
			}
		}
		return &authorization.Response{
			Allow: false,
			Msg:   "Not enough Memory",
		}

	}

	return &authorization.Response{
		Allow: true,
	}
}

// AuthZRes always allow responses from server
func (f *basicAuthorizer) AuthZRes(authZReq *authorization.Request) *authorization.Response {

	return &authorization.Response{Allow: true}

}
