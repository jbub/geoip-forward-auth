package main

import (
	"log"
	"os"

	"github.com/jbub/geoip-forward-auth/internal/cmd"
	"github.com/jbub/geoip-forward-auth/internal/version"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name: "geoip-forward-auth",
		Commands: []*cli.Command{
			cmd.Server,
		},
		Version: version.Version,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
