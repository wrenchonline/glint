package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"glint/ast"
	"glint/brohttp"
	"glint/config"
	"glint/crawler"
	"glint/csrf"
	"glint/dbmanager"
	"glint/logger"
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
var WebSocket string
var Socket string

type Task struct {
	TaskId        int
	XssSpider     brohttp.Spider
	Targets       []*model.Request
	TaskConfig    config.TaskConfig
	PluginWg      sync.WaitGroup
	Plugins       []*plugin.Plugin
	Ctx           *context.Context //当前任务的现场
	Cancel        *context.CancelFunc
	lock          *sync.Mutex
	Dm            *dbmanager.DbManager
	InstallDb     bool
	Progress      float64
	DoStartSignal chan bool
	PliuginsMsg   chan map[string]interface{}
}

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
		Version:   "v0.1.2",
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

			//设置websocket地址
			&cli.StringFlag{
				Name: "websocket",
				// Aliases:     []string{"p"},
				Usage:       "Websocket Communication Address. Example `--websocket 127.0.0.1:8081`",
				Value:       DefaultSocket,
				Destination: &WebSocket,
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
		logger.Error(err.Error())
	}

}

func run(c *cli.Context) error {
	// var req model.Request
	logger.DebugEnable(false)
	signalChan = make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	if strings.ToLower(WebSocket) != "" {
		WebSocketHandler(c)
	} else if strings.ToLower(Socket) != "" {
		SocketHandler(c)
	} else {
		if c.Args().Len() == 0 {
			logger.Error("url must be set")
			return errors.New("url must be set")
		}
		t := Task{TaskId: 65535}
		t.Init()
		CmdHandler(c, &t)
	}
	return nil
}

func (t *Task) waitquit(c *crawler.CrawlerTask) {
	select {
	case <-signalChan:
		logger.Warning("Interput exit ...")
		c.Pool.Tune(1)
		c.Pool.Release()
		c.Browser.Close()
		c.PluginBrowser.Close()
		os.Exit(-1)
	case <-(*t.Ctx).Done():
		logger.Success("Task exit ...")
		if !c.Pool.IsClosed() {
			c.Pool.Tune(1)
			c.Pool.Release()
			c.Browser.Close()
			c.PluginBrowser.Close()
		}
		if len(t.Plugins) != 0 {
			for _, plugin := range t.Plugins {
				plugin.Pool.Tune(1)
				// plugin.Pool.Release()
				(*plugin.Cancel)()
				if plugin.Spider != nil {
					plugin.Spider.Close()
				}
			}
		}
	}
}

//删除数据库内容
func (t *Task) deletedbresult() error {
	err := t.Dm.DeleteScanResult(t.TaskId)
	if err != nil {
		logger.Error(err.Error())
	}
	return err
}

func (t *Task) close() {
	//由外部socket关闭避免重复释放
	if _, ok := (*t.Ctx).Deadline(); !ok {
		(*t.Cancel)()
	}
}

func (t *Task) setprog(progress float64) {
	// p := util.Decimal(progress)
	t.lock.Lock()
	t.Progress += progress
	t.lock.Unlock()
}

//发送进度条到通知队列
func (t *Task) sendprog() {
	Element := make(map[string]interface{})
	Element["status"] = 1
	Element["progress"] = t.Progress
	t.PliuginsMsg <- Element
}

func (t *Task) dostartTasks(installDb bool) error {
	var err error
	ReqList := make(map[string][]interface{})
	List := make(map[string][]ast.JsonUrl)
	t.DoStartSignal <- true
	if installDb {
		t.deletedbresult()
	}
	//完成后通知上下文
	defer t.close()

	StartPlugins := Plugins.Value()
	percentage := 1 / float64(len(StartPlugins)+1)
	Crawtask, err := crawler.NewCrawlerTask(t.Ctx, t.Targets, t.TaskConfig)
	t.XssSpider.Init(t.TaskConfig)
	Crawtask.PluginBrowser = &t.XssSpider
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	go t.waitquit(Crawtask)

	logger.Info("Start crawling.")
	//Crawtask.Run()是同步函数
	Crawtask.Run()
	result := Crawtask.Result
	logger.Info(fmt.Sprintf("Task finished, %d results, %d requests, %d subdomains, %d domains found.",
		len(result.ReqList), len(result.AllReqList), len(result.SubDomainList), len(result.AllDomainList)))

	if Crawtask.Deadline() {
		goto quit
	}

	t.setprog(percentage)

	t.sendprog()

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
	//Crawtask.PluginBrowser = t.XssSpider
	//爬完虫加载插件检测漏洞
	for _, PluginName := range StartPlugins {
		switch strings.ToLower(PluginName) {
		case "csrf":
			myfunc := []plugin.PluginCallback{}
			myfunc = append(myfunc, csrf.Csrfeval)
			pluginInternal := plugin.Plugin{
				PluginName:   PluginName,
				MaxPoolCount: 20,
				Callbacks:    myfunc,
				InstallDB:    installDb,
				Taskid:       t.TaskId,
				Timeout:      time.Second * 600,
				Progperc:     percentage,
			}
			pluginInternal.Init()
			t.PluginWg.Add(1)
			t.lock.Lock()
			t.Plugins = append(t.Plugins, &pluginInternal)
			t.lock.Unlock()
			args := plugin.PluginOption{
				PluginWg:  &t.PluginWg,
				Progress:  &t.Progress,
				IsSocket:  true,
				Data:      ReqList,
				TaskId:    t.TaskId,
				SingelMsg: &t.PliuginsMsg,
				Totalprog: percentage,
			}
			go func() {
				pluginInternal.Run(args)
			}()
		case "xss":
			myfunc := []plugin.PluginCallback{}
			myfunc = append(myfunc, xsschecker.CheckXss)
			pluginInternal := plugin.Plugin{
				PluginName:   "xss",
				MaxPoolCount: 20,
				Callbacks:    myfunc,
				Spider:       &t.XssSpider,
				InstallDB:    installDb,
				Taskid:       t.TaskId,
				Timeout:      time.Second * 900,
				Progperc:     percentage,
			}
			pluginInternal.Init()
			t.PluginWg.Add(1)
			t.lock.Lock()
			t.Plugins = append(t.Plugins, &pluginInternal)
			t.lock.Unlock()

			args := plugin.PluginOption{
				PluginWg:  &t.PluginWg,
				Progress:  &t.Progress,
				IsSocket:  true,
				Data:      ReqList,
				TaskId:    t.TaskId,
				SingelMsg: &t.PliuginsMsg,
				Totalprog: percentage,
			}
			go func() {
				pluginInternal.Run(args)
			}()
		}
	}
	t.PluginWg.Wait()
quit:
	Taskslock.Lock()
	removetasks(t.TaskId)
	if installDb {
		t.SavePluginResult()
	}
	Taskslock.Unlock()
	logger.Info("The End for task:%d", t.TaskId)
	return err
}

func (t *Task) SavePluginResult() {
	for _, plugin := range t.Plugins {
		funk.Map(plugin.ScanResult, func(s *util.ScanResult) bool {
			err := t.Dm.SaveScanResult(t.TaskId, plugin.PluginName,
				s.Vulnerable,
				s.Target,
				s.Output,
				base64.StdEncoding.EncodeToString([]byte(s.ReqMsg[0])),
				base64.StdEncoding.EncodeToString([]byte(s.RespMsg[0])),
				s.VulnerableLevel)
			if err != nil {
				logger.Error(err.Error())
				return false
			}
			return true
		})
	}
}

//removetasks 移除总任务进度的任务ID
func removetasks(id int) {
	for index, t := range Tasks {
		if t.TaskId == id {
			Tasks = append(Tasks[:index], Tasks[index+1:]...)
		}
	}
}

func (t *Task) Init() {
	Ctx, Cancel := context.WithCancel(context.Background())
	t.Ctx = &Ctx
	t.Cancel = &Cancel
	t.lock = &sync.Mutex{}
	t.PliuginsMsg = make(chan map[string]interface{})
	t.DoStartSignal = make(chan bool)
}

func (t *Task) UrlPackage(_url string) error {
	var err error
	Headers := make(map[string]interface{})
	if !strings.HasPrefix(_url, "http") {
		err = errors.New(`parameter error,please "http(s)://" start with Url `)
		logger.Error(err.Error())
		return err
	}
	url, err := model.GetUrl(_url)
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	Headers["HOST"] = url.Path
	t.Targets = append(t.Targets, &model.Request{
		URL:           url,
		Method:        "GET",
		FasthttpProxy: t.TaskConfig.Proxy,
		Headers:       Headers,
	})
	return err
}

func CmdHandler(c *cli.Context, t *Task) {
	logger.Info("Enter command mode...")
	err := config.ReadTaskConf(ConfigpPath, &t.TaskConfig)
	if err != nil {
		logger.Error("test ReadTaskConf() fail")
	}
	for _, _url := range c.Args().Slice() {
		t.UrlPackage(_url)
	}
	t.dostartTasks(false)
	t.PluginWg.Wait()
}

func WebSocketHandler(c *cli.Context) error {
	l, err := net.Listen("tcp", WebSocket)
	if err != nil {
		return err
	}
	logger.Info("listening on http://%v", l.Addr())

	cs, err := NewTaskServer("websocket")
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	s := &http.Server{
		Handler: cs,
	}

	errc := make(chan error, 1)
	go func() {
		errc <- s.Serve(l)
	}()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)

	select {
	case err := <-errc:
		logger.Error("failed to serve: %v", err)
	case sig := <-sigs:
		logger.Error("terminating: %v", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	return s.Shutdown(ctx)
}

func SocketHandler(c *cli.Context) error {
	var m MConn
	m.Init()
	server_control, err := NewTaskServer("socket")
	m.CallbackFunc = server_control.Task
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	listener, err := net.Listen("tcp", Socket)
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	defer listener.Close()
	for {
		con, err := listener.Accept()
		if err != nil {
			logger.Error(err.Error())
			continue
		}
		go m.Listen(con)
		SOCKETCONN = append(SOCKETCONN, &con)
	}
}
