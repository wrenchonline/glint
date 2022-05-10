package main

import (
	"context"
	"errors"
	"fmt"
	"glint/ast"
	"glint/brohttp"
	"glint/cmdinject"
	"glint/config"
	"glint/crawler"
	"glint/crlf"
	"glint/csrf"
	"glint/dbmanager"
	"glint/jsonp"
	"glint/logger"
	"glint/model"
	"glint/plugin"
	"glint/proxy"
	"glint/ssrfcheck"
	"glint/util"
	"glint/xsschecker"
	"glint/xxe"
	"net"
	"net/http"
	_ "net/http/pprof"
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

var DefaultPlugins = cli.NewStringSlice("xss", "csrf", "cmdinject", "jsonp", "xxe", "crlf") //,"ssrf"
var signalChan chan os.Signal
var ConfigpPath string
var Plugins cli.StringSlice
var WebSocket string
var Socket string
var PassiveProxy bool
var GenerateCA bool
var Dbconect bool

type Task struct {
	TaskId        int
	HostIds       []int
	XssSpider     brohttp.Spider
	Targets       []*model.Request
	TaskConfig    config.TaskConfig
	PluginWg      sync.WaitGroup
	Plugins       []*plugin.Plugin
	Ctx           *context.Context //当前任务的现场
	Cancel        *context.CancelFunc
	lock          *sync.Mutex
	Dm            *dbmanager.DbManager
	ScartTime     time.Time
	EndTime       time.Time
	InstallDb     bool
	Progress      float64
	DoStartSignal chan bool
	PliuginsMsg   chan map[string]interface{}
	Status        util.Status
	ScanType      int //扫描模式
}

type tconfig struct {
	InstallDb     bool
	EnableCrawler bool
	ProxyPort     int64
	HttpsCert     string
	HttpsCertKey  string
}

func main() {

	go func() {
		ip := "0.0.0.0:6060"
		if err := http.ListenAndServe(ip, nil); err != nil {
			fmt.Printf("start pprof failed on %s\n", ip)
		}
	}()

	author := cli.Author{
		Name:  "wrench",
		Email: "ljl260435988@gmail.com",
	}

	// PassiveProxy := cli.Author{
	// 	Name:  "passiveproxy",
	// 	Email: "ljl260435988@gmail.com",
	// }

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
				Usage:       "socket Communication Address. Example `--socket 127.0.0.1:8081`",
				Value:       DefaultSocket,
				Destination: &Socket,
			},
			&cli.BoolFlag{
				Name: "passiveproxy",
				// Aliases:     []string{"p"},
				Usage:       "start passiveproxy",
				Value:       false,
				Destination: &PassiveProxy,
			},
			&cli.BoolFlag{
				Name: "generate-ca-cert",
				// Aliases:     []string{"p"},
				Usage:       "generate CA certificate and private key for MITM",
				Value:       false,
				Destination: &GenerateCA,
			},
			&cli.StringFlag{
				Name: "cert",
				// Aliases:     []string{"p"},
				Usage:       "import certificate path",
				Value:       "",
				Destination: &Cert,
			},
			&cli.StringFlag{
				Name: "key",
				// Aliases:     []string{"p"},
				Usage:       "import certificate private key path",
				Value:       "",
				Destination: &PrivateKey,
			},

			&cli.BoolFlag{
				Name: "dbconnect",
				// Aliases:     []string{"c"},
				Usage:       "Wherever Database Connect",
				Value:       false,
				Destination: &Dbconect,
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
	} else if PassiveProxy {
		// if c.Args().Len() == 0 {
		// 	logger.Error("url must be set")
		// 	return errors.New("url must be set")
		// }
		t := Task{TaskId: 65535}
		t.Init()
		CmdHandler(c, &t)
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

func craw_cleanup(c *crawler.CrawlerTask) {
	if !c.Pool.IsClosed() {
		c.Pool.Tune(1)
		c.Pool.Release()
		c.Browser.Close()
		// c.PluginBrowser.Close()
	}
}

// func (t *Task) task_cleanup() {
// 	if len(t.Plugins) != 0 {
// 		for _, plugin := range t.Plugins {
// 			plugin.Pool.Tune(1)
// 			(*plugin.Cancel)()
// 			if plugin.Spider != nil {
// 				plugin.Spider.Close()
// 			}
// 		}
// 	}
// }

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
	//删除插件
	if len(t.Plugins) != 0 {
		for _, plugin := range t.Plugins {
			plugin.Pool.Tune(1)
			(*plugin.Cancel)()
			if plugin.Spider != nil {
				plugin.Spider.Close()
			}
		}
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

//bpayloadbrower 该插件是否开启浏览器方式发送payload
func (t *Task) AddPlugins(
	PluginName string,
	PluginId plugin.Plugin_type,
	callback plugin.PluginCallback,
	ReqList map[string]interface{},
	installDb bool,
	percentage float64,
	bpayloadbrower bool,
	HttpsCert string,
	HttpsCertKey string) {
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, callback)
	var Payloadcarrier *brohttp.Spider
	if bpayloadbrower {
		Payloadcarrier = &t.XssSpider
	} else {
		Payloadcarrier = nil
	}

	pluginInternal := plugin.Plugin{
		PluginName:   PluginName,
		PluginId:     PluginId,
		MaxPoolCount: 20,
		Callbacks:    myfunc,
		InstallDB:    installDb,
		Spider:       Payloadcarrier,
		Taskid:       t.TaskId,
		Timeout:      time.Second * 600,
		Progperc:     percentage,
		Dm:           t.Dm,
	}
	pluginInternal.Init()
	t.PluginWg.Add(1)
	t.lock.Lock()
	t.Plugins = append(t.Plugins, &pluginInternal)
	t.lock.Unlock()
	args := plugin.PluginOption{
		PluginWg:     &t.PluginWg,
		Progress:     &t.Progress,
		IsSocket:     true,
		Data:         ReqList,
		TaskId:       t.TaskId,
		SingelMsg:    &t.PliuginsMsg,
		Totalprog:    percentage,
		HttpsCert:    HttpsCert,
		HttpsCertKey: HttpsCertKey,
	}
	go func() {
		pluginInternal.Run(args)
	}()
}

func (t *Task) dostartTasks(config tconfig) error {
	var (
		err       error
		crawtasks []*crawler.CrawlerTask
		Results   []*crawler.Result
	)

	ReqList := make(map[string][]interface{})
	ReqList1 := make(map[string]interface{})
	List := make(map[string][]ast.JsonUrl)

	if config.InstallDb {
		t.deletedbresult()
	}
	//完成后通知上下文
	defer t.close()
	// defer t.task_cleanup()

	StartPlugins := Plugins.Value()
	percentage := 1 / float64(len(StartPlugins)+1)
	logger.Info("config.EnableCrawler: %v", config.EnableCrawler)
	if config.EnableCrawler {

		for _, Target := range t.Targets {
			Crawtask, err := crawler.NewCrawlerTask(t.Ctx, Target, t.TaskConfig)
			Crawtask.Result.Hostid = Target.DomainId
			t.XssSpider.Init(t.TaskConfig)
			Crawtask.PluginBrowser = &t.XssSpider
			if err != nil {
				logger.Error(err.Error())
				return err
			}
			logger.Info("Start crawling.")
			crawtasks = append(crawtasks, Crawtask)
			//Crawtask.Run()是同步函数
			go Crawtask.Run()
		}

		//等待爬虫结束
		for _, crawtask := range crawtasks {
			//这个是真正等待结束
			crawtask.Waitforsingle()
			go craw_cleanup(crawtask)
			result := crawtask.Result
			result.Hostid = crawtask.Result.Hostid
			Results = append(Results, result)
			logger.Info(fmt.Sprintf("Task finished, %d results, %d requests, %d subdomains, %d domains found.",
				len(result.ReqList), len(result.AllReqList), len(result.SubDomainList), len(result.AllDomainList)))
		}

		t.setprog(percentage)

		t.sendprog()
		for _, result := range Results {
			funk.Map(result.ReqList, func(r *model.Request) bool {
				element0 := ast.JsonUrl{
					Url:     r.URL.String(),
					MetHod:  r.Method,
					Headers: r.Headers,
					Data:    r.PostData,
					Source:  r.Source,
					Hostid:  result.Hostid,
				}
				element := make(map[string]interface{})
				element["url"] = r.URL.String()
				element["method"] = r.Method
				element["headers"] = r.Headers
				element["data"] = r.PostData
				element["source"] = r.Source
				element["hostid"] = result.Hostid

				ReqList[r.GroupsId] = append(ReqList[r.GroupsId], element)
				List[r.GroupsId] = append(List[r.GroupsId], element0)
				return false
			})
		}
		util.SaveCrawOutPut(List, "result.json")

		for s, v := range ReqList {
			ReqList1[s] = v
		}

		//Crawtask.PluginBrowser = t.XssSpider
		//爬完虫加载插件检测漏洞
		for _, PluginName := range StartPlugins {
			switch strings.ToLower(PluginName) {
			case "csrf":
				t.AddPlugins("CSRF", plugin.Csrf, csrf.Csrfeval, ReqList1, config.InstallDb, percentage, false, config.HttpsCert, config.HttpsCertKey)
			case "xss":
				t.AddPlugins("XSS", plugin.Xss, xsschecker.CheckXss, ReqList1, config.InstallDb, percentage, true, config.HttpsCert, config.HttpsCertKey)
			case "ssrf":
				t.AddPlugins("SSRF", plugin.Ssrf, ssrfcheck.Ssrf, ReqList1, config.InstallDb, percentage, false, config.HttpsCert, config.HttpsCertKey)
			case "jsonp":
				t.AddPlugins("JSONP", plugin.Jsonp, jsonp.JsonpValid, ReqList1, config.InstallDb, percentage, false, config.HttpsCert, config.HttpsCertKey)
			case "cmdinject":
				t.AddPlugins("CMDINJECT", plugin.CmdInject, cmdinject.CmdValid, ReqList1, config.InstallDb, percentage, false, config.HttpsCert, config.HttpsCertKey)
			case "xxe":
				t.AddPlugins("XXE", plugin.Xxe, xxe.Xxe, ReqList1, false, 0., false, config.HttpsCert, config.HttpsCertKey)
			case "crlf":
				t.AddPlugins("CRLF", plugin.Crlf, crlf.Crlf, ReqList1, false, 0., false, config.HttpsCert, config.HttpsCertKey)
			}
		}

		t.PluginWg.Wait()
		// quit:
		Taskslock.Lock()
		removetasks(t.TaskId)
		Taskslock.Unlock()
		if config.InstallDb {
			t.SaveQuitTime()
		}
		logger.Info("The End for task:%d", t.TaskId)
	} else {
		//不开启爬虫启动被动代理模式
		s := SProxy{}
		s.CallbackFunc = t.agentPluginRun
		s.Run()
	}

	return err
}

func (t *Task) SaveQuitTime() {
	t.EndTime = time.Now()
	otime := time.Since(t.ScartTime)
	over_time := util.FmtDuration(otime)
	t.Dm.SaveQuitTime(t.TaskId, t.EndTime, over_time)
}

func (t *Task) agentPluginRun(args interface{}) {
	StartPlugins := Plugins.Value()
	if p, ok := args.(*proxy.PassiveProxy); ok {
		go func() {
			for {
				urlinfo := <-p.CommunicationSingleton
				//logger.Info("Obtain url:%s", urlinfo["agent"]["url"])
				for _, PluginName := range StartPlugins {
					switch strings.ToLower(PluginName) {
					case "csrf":
						t.AddPlugins("CSRF", plugin.Csrf, csrf.Csrfeval, urlinfo, false, 0., false, p.HttpsCert, p.HttpsCertKey)
					case "xss":
						t.AddPlugins("XSS", plugin.Xss, xsschecker.CheckXss, urlinfo, false, 0., true, p.HttpsCert, p.HttpsCertKey)
					case "ssrf":
						t.AddPlugins("SSRF", plugin.Ssrf, ssrfcheck.Ssrf, urlinfo, false, 0., false, p.HttpsCert, p.HttpsCertKey)
					case "jsonp":
						t.AddPlugins("JSONP", plugin.Jsonp, jsonp.JsonpValid, urlinfo, false, 0., false, p.HttpsCert, p.HttpsCertKey)
					case "cmdinject":
						t.AddPlugins("CMDINJECT", plugin.CmdInject, cmdinject.CmdValid, urlinfo, false, 0., false, p.HttpsCert, p.HttpsCertKey)
					case "xxe":
						t.AddPlugins("XXE", plugin.Xxe, xxe.Xxe, urlinfo, false, 0., false, p.HttpsCert, p.HttpsCertKey)
					case "crlf":
						t.AddPlugins("CRLF", plugin.Crlf, crlf.Crlf, urlinfo, false, 0., false, p.HttpsCert, p.HttpsCertKey)
					}

				}
				//t.PluginWg.Wait()
				//logger.Info("origin url:%s has finished", urlinfo["url"])
			}
		}()
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
	t.ScartTime = time.Now()
}

func (t *Task) UrlPackage(_url string, extra interface{}) error {
	var (
		err      error
		Domainid int64
	)

	if id, ok := extra.(int64); ok {
		Domainid = id
	}

	Headers := make(map[string]interface{})

	_url = util.RepairUrl(_url)

	// if !(strings.HasPrefix(_url, "http") || strings.HasPrefix(_url, "https")) {
	// 	err = errors.New(`parameter error,please "http(s)://" start with Url `)
	// 	logger.Error(err.Error())
	// 	return err
	// }

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
		DomainId:      Domainid,
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
		t.UrlPackage(_url, nil)
	}
	t.XssSpider.Init(t.TaskConfig)
	//t.PluginBrowser = &t.XssSpider
	config := tconfig{}
	config.EnableCrawler = false
	config.InstallDb = false
	config.ProxyPort = 1966
	t.dostartTasks(config)
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
	errc := make(chan error, 1)
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
	go func() {
		for {
			con, err := listener.Accept()
			if err != nil {
				logger.Error(err.Error())
				continue
			}
			go m.Listen(con)
			SOCKETCONN = append(SOCKETCONN, &con)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)

	select {
	case err := <-errc:
		logger.Error("failed to serve: %v", err)
	case sig := <-sigs:
		logger.Error("terminating: %v", sig)
	}

	return err
}
