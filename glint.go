package main

import (
	"errors"
	"fmt"
	"glint/config"
	"glint/crawler"
	"glint/log"
	"glint/model"
	"os"
	"os/signal"
	"strings"

	"github.com/urfave/cli/v2"
)

const (
	DefaultConfigPath string = "config.yaml"
)

var DefaultPlugins = cli.NewStringSlice("xss", "csrf")
var signalChan chan os.Signal
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
				Name: "config",
				// Aliases:     []string{"c"},
				Usage:       "Scan Profile, Example `-c config.yaml`",
				Value:       DefaultConfigPath,
				Destination: &ConfigpPath,
			},
			//设置需要开启的插件
			&cli.StringSliceFlag{
				Name: "plugin",
				// Aliases:     []string{"p"},
				Usage:       "Vulnerable Plugin, Example `--plugin xss csrf ..., The same moudle`",
				Value:       DefaultPlugins,
				Destination: &Plugins,
			},
		},
		Action: run,
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Error(err.Error())
	}

}

func run(c *cli.Context) error {
	// var req model.Request
	Plugins := Plugins.Get().([]string)
	targets := []*model.Request{}
	signalChan = make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	if c.Args().Len() == 0 {
		log.Error("url must be set")
		return errors.New("url must be set")
	}

	TaskConfig := config.TaskConfig{}
	err := config.ReadTaskConf(ConfigpPath, &TaskConfig)
	if err != nil {
		log.Error("test ReadTaskConf() fail")
	}

	for _, _url := range c.Args().Slice() {
		if !strings.HasPrefix(_url, "http") {
			log.Error(`Parameter Error,Please "http(s)://" start with Url `)
			os.Exit(-1)
		}
		url, err := model.GetUrl(_url)
		if err != nil {
			log.Error(err.Error())
		}
		Headers := make(map[string]interface{})
		Headers["HOST"] = url.Path
		targets = append(targets, &model.Request{
			URL:           url,
			Method:        "GET",
			FasthttpProxy: TaskConfig.Proxy,
			Headers:       Headers,
		})
	}

	task, err := crawler.NewCrawlerTask(targets, TaskConfig)
	go WaitInterputQuit(task)
	log.Info("Start crawling.")
	task.Run()
	result := task.Result
	log.Info(fmt.Sprintf("Task finished, %d results, %d requests, %d subdomains, %d domains found.",
		len(result.ReqList), len(result.AllReqList), len(result.SubDomainList), len(result.AllDomainList)))

	for _, Plugin := range Plugins {

	}

	return nil
}

func WaitInterputQuit(t *crawler.CrawlerTask) {
	select {
	case <-signalChan:
		fmt.Println("exit ...")
		t.Pool.Tune(1)
		t.Pool.Release()
		t.Browser.Close()
		os.Exit(-1)
	}
}
