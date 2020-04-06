package main

import (
	"log"
	"os"

	"github.com/urfave/cli"
)

const version = "0.0.1"

var cmdList = []cli.Command{}

func main() {
	app := cli.NewApp()
	app.Name = "aws-check-cli"
	app.Version = version
	app.Usage = "cli for aws checker"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "region",
			Usage:  "aws region",
			EnvVar: "AWS_REGION",
		},
	}
	app.Commands = cmdList
	err := app.Run(os.Args)
	handleError(err)
}

type subCmd interface {
	Run(*cli.Context, string) error
}

func action(c *cli.Context, sc subCmd) error {
	g := c.GlobalString("region")
	return sc.Run(c, g)
}

func handleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
