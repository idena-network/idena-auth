package main

import (
	"github.com/idena-network/idena-auth/config"
	"gopkg.in/urfave/cli.v1"
	"os"
)

func main() {
	app := cli.NewApp()
	app.Name = "github.com/idena-network/idena-auth"
	app.Version = "0.0.1"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Usage: "Config file",
			Value: "config.json",
		},
	}
	app.Action = func(context *cli.Context) error {
		appConfig := config.LoadConfig(context.String("config"))
		startServer(appConfig)
		return nil
	}
	app.Run(os.Args)
}
