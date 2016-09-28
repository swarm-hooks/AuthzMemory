// broker consists of the entry point for the twistlock authz broker
package main

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/memAuditAuthz/authz"
	"github.com/memAuditAuthz/core"
)

const (
	debugFlag      = "debug"
	authorizerFlag = "authz-handler"
)

const (
	authorizerBasic = "basic"
)

func main() {

	app := cli.NewApp()
	app.Name = "twistlock-authz"
	app.Usage = "Authorization plugin for docker"
	app.Version = "1.0"

	app.Action = func(c *cli.Context) {

		// initLogger(c.GlobalBool(debugFlag))

		var authZHandler core.Authorizer

		switch c.GlobalString(authorizerFlag) {
		case authorizerBasic:
			authZHandler = authz.NewBasicAuthZAuthorizer(&authz.BasicAuthorizerSettings{})
		default:
			panic(fmt.Sprintf("Unkwon authz hander %q", c.GlobalString(authorizerFlag)))
		}

		srv := core.NewAuthZSrv(authZHandler)
		err := srv.Start()

		if err != nil {
			panic(err)
		}

	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:   debugFlag,
			Usage:  "Enable debug mode",
			EnvVar: "DEBUG",
		},

		cli.StringFlag{
			Name:   authorizerFlag,
			Value:  authorizerBasic,
			EnvVar: "AUTHORIZER",
			Usage:  "Defines the authz handler type",
		},
	}

	app.Run(os.Args)
}

// initLogger initialize the logger based on the log level
func initLogger(debug bool) {

	logrus.SetFormatter(&logrus.TextFormatter{})
	// Output to stderr instead of stdout, could also be a file.
	logrus.SetOutput(os.Stdout)
	// Only log the warning severity or above.
	logrus.SetLevel(logrus.DebugLevel)
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
}
