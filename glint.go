package main

import (
	"context"
	"errors"
	"fmt"
	"glint/ast"
	"glint/brohttp"
	"glint/config"
	"glint/crawler"
	"glint/csrf"
	"glint/log"
	"glint/model"
	"glint/plugin"
	"glint/util"
	"glint/xsschecker"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/thoas/go-funk"
	"github.com/urfave/cli/v2"
)

const (
	DefaultConfigPath string = "config.yaml"
	DefaultSocket     string = ""
)

var DefaultPlugins = cli.NewStringSlice("xss", "csrf")
var signalChan chan os.Signal
var ConfigpPath string
var Plugins cli.StringSlice
var Socket string

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

			//设置socket地址
			&cli.StringFlag{
				Name: "socket",
				// Aliases:     []string{"p"},
				Usage:       "Websocket Communication Address. Example `--socket 127.0.0.1:8081`",
				Value:       DefaultSocket,
				Destination: &Socket,
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
	log.DebugEnable(false)
	signalChan = make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	if Socket != "" {
		ServerHandler(c)
	} else {
		if c.Args().Len() == 0 {
			log.Error("url must be set")
			return errors.New("url must be set")
		}
		CmdHandler(c)
	}
	return nil
}

func WaitInterputQuit(t *crawler.CrawlerTask) {
	select {
	case <-signalChan:
		fmt.Println("exit ...")
		t.Pool.Tune(1)
		t.Pool.Release()
		t.PluginBrowser.Close()
		t.Browser.Close()
		os.Exit(-1)
	}
}

func CmdHandler(c *cli.Context) {
	Spider := brohttp.Spider{}
	Spider.Init()
	Plugins := Plugins.Value()
	targets := []*model.Request{}
	var PluginWg sync.WaitGroup
	log.Info("Enter command mode...")
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

	ReqList := make(map[string][]interface{})
	List := make(map[string][]ast.JsonUrl)
	funk.Map(result.ReqList, func(r *model.Request) bool {
		element0 := ast.JsonUrl{
			Url:     r.URL.String(),
			MetHod:  r.Method,
			Headers: r.Headers,
			Data:    r.PostData,
			Source:  r.Source}
		element := make(map[string]interface{})
		element["url"] = r.URL.String()
		element["method"] = r.Method
		element["headers"] = r.Headers
		element["data"] = r.PostData
		element["source"] = r.Source
		ReqList[r.GroupsId] = append(ReqList[r.GroupsId], element)
		List[r.GroupsId] = append(List[r.GroupsId], element0)
		return false
	})

	util.SaveCrawOutPut(List, "result.json")

	task.PluginBrowser = &Spider
	//爬完虫加载插件检测漏洞
	for _, PluginName := range Plugins {
		switch strings.ToLower(PluginName) {
		case "csrf":
			myfunc := []plugin.PluginCallback{}
			myfunc = append(myfunc, csrf.Origin, csrf.Referer)
			plugin := plugin.Plugin{
				PluginName:   PluginName,
				MaxPoolCount: 20,
				Callbacks:    myfunc,
			}
			plugin.Init()
			PluginWg.Add(1)
			go func() {
				plugin.Run(ReqList, &PluginWg)
			}()
		case "xss":
			// Spider.Init()
			myfunc := []plugin.PluginCallback{}
			myfunc = append(myfunc, xsschecker.CheckXss)
			plugin := plugin.Plugin{
				PluginName:   "xss",
				MaxPoolCount: 1,
				Callbacks:    myfunc,
				Spider:       &Spider,
			}
			plugin.Init()
			PluginWg.Add(1)
			go func() {
				plugin.Run(ReqList, &PluginWg)
			}()
		}
	}
	PluginWg.Wait()
}

func ServerHandler(c *cli.Context) error {
	l, err := net.Listen("tcp", Socket)
	if err != nil {
		return err
	}
	log.Info("listening on http://%v", l.Addr())
	cs := NewTaskServer()

	s := &http.Server{
		Handler:      cs,
		ReadTimeout:  time.Second * 10,
		WriteTimeout: time.Second * 10,
	}

	errc := make(chan error, 1)
	go func() {
		errc <- s.Serve(l)
	}()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)

	select {
	case err := <-errc:
		log.Error("failed to serve: %v", err)
	case sig := <-sigs:
		log.Error("terminating: %v", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	return s.Shutdown(ctx)
}
