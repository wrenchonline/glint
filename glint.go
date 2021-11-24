package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

const (
	DefaultConfigPath string = "config.yaml"
)

var DefaultPlugins = cli.NewStringSlice("xss", "csrf")

var ConfigpPath string
var Plugins cli.StringSlice

func main() {
	author := cli.Author{
		Name:  "wrench",
		Email: "ljl260435988@gmail.com",
	}
	app := &cli.App{
		// UseShortOptionHandling: true,
		Name:      "glint",
		Usage:     "A web vulnerability scanners",
		UsageText: "glint [global options] url1 url2 url3 ... (must be same host)",
		Version:   "v0.1.0",
		Authors:   []*cli.Author{&author},
		Flags: []cli.Flag{
			//设置配置文件路径
			&cli.StringFlag{
				Name:        "config",
				Aliases:     []string{"c"},
				Usage:       "Scan Profile, Example `-c config.yaml`",
				Value:       DefaultConfigPath,
				Destination: &ConfigpPath,
			},
			//设置需要开启的插件
			&cli.StringSliceFlag{
				Name:        "plugin",
				Aliases:     []string{"p"},
				Usage:       "Vulnerable Plugin, Example `--plugin xss csrf ..., The same moudle`",
				Value:       DefaultPlugins,
				Destination: &Plugins,
			},
		},
		Action: run,
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}

func run(c *cli.Context) error {

	return nil
}
