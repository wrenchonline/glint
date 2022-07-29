package plugin

import (
	"context"
	"encoding/base64"
	"glint/config"
	"glint/dbmanager"
	"glint/logger"
	"glint/nenet"
	"glint/util"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
)

type Plugin_type string

const (
	Xss       Plugin_type = "rj-001-0001"
	Csrf      Plugin_type = "rj-002-0001"
	Ssrf      Plugin_type = "rj-003-0001"
	Jsonp     Plugin_type = "rj-004-0001"
	CmdInject Plugin_type = "rj-005-0001"
	Xxe       Plugin_type = "rj-006-0001"
	Crlf      Plugin_type = "rj-007-0001"
	CORS      Plugin_type = "rj-008-0001"
	SQL       Plugin_type = "rj-009-0001"
	TLS       Plugin_type = "rj-010-0001"
	APPERROR  Plugin_type = "rj-011-0001"
	CSP       Plugin_type = "rj-012-0001"
	DIR_COSS  Plugin_type = "rj-013-0001"
)

type Plugin struct {
	Taskid       int    //任务id，只有插入数据库的时候使用
	PluginName   string //插件名
	PluginId     Plugin_type
	MaxPoolCount int                //协程池最大并发数
	Callbacks    []PluginCallback   //扫描插件函数
	Pool         *ants.PoolWithFunc //
	threadwg     sync.WaitGroup     //同步线程
	ScanResult   []*util.ScanResult
	mu           sync.Mutex
	Progperc     float64 //总进度百分多少
	Spider       *nenet.Spider
	InstallDB    bool //是否插入数据库
	Ctx          *context.Context
	Cancel       *context.CancelFunc
	Timeout      time.Duration
	Dm           *dbmanager.DbManager //数据库句柄
	Rate         *util.Rate
}

type PluginOption struct {
	PluginWg      *sync.WaitGroup
	Progress      *float64 //此任务进度
	Totalprog     float64  //此插件占有的总进度
	IsSocket      bool
	Data          map[string]interface{}
	SingelMsg     *chan map[string]interface{}
	TaskId        int    //该插件所属的taskid
	Bstripurl     bool   //是否分开groupurl
	HttpsCert     string //
	HttpsCertKey  string //
	IsAllUrlsEval bool   //是否传递所有URLS给当前某个漏洞插件传递。适合用于一个漏洞报告所有同域名的URLS
	Rate          *util.Rate
	Config        *config.TaskConfig
	// XssTimeOut   time.Duration //xss扫描总超时
}

type GroupData struct {
	GroupType    string
	Url          map[string]interface{}
	GroupUrls    []interface{}
	Spider       *nenet.Spider
	Pctx         *context.Context
	Pcancel      *context.CancelFunc
	IsSocket     bool
	Msg          *chan map[string]interface{}
	HttpsCert    string //
	HttpsCertKey string //
	Config       *config.TaskConfig
	Rate         *util.Rate
	// XssTimeOut   time.Duration //xss扫描总超时
}

func (p *Plugin) Init() {
	p.Pool, _ = ants.NewPoolWithFunc(p.MaxPoolCount, func(args interface{}) { //新建一个带有同类方法的pool对象
		var Result_id int64
		defer p.threadwg.Done()
		data := args.(GroupData)
		for _, f := range p.Callbacks {
			scanresult, isVuln, err := f(data)
			if err != nil {
				logger.Debug("plugin::error %s", err.Error())
			} else {
				if isVuln {
					//在这里保存,在这里抛出信息给web前端
					if scanresult != nil {
						p.mu.Lock()
						p.ScanResult = append(p.ScanResult, scanresult)
						p.mu.Unlock()
						Element := make(map[string]interface{})

						if p.InstallDB {
							Result_id, _ = p.Dm.SaveScanResult(
								p.Taskid,
								string(p.PluginId),
								scanresult.Vulnerable,
								scanresult.Target,
								// s.Output,1
								base64.StdEncoding.EncodeToString([]byte(scanresult.ReqMsg[0])),
								base64.StdEncoding.EncodeToString([]byte(scanresult.RespMsg[0])),
								int(scanresult.Hostid),
							)
						}

						Element["status"] = 3
						Element["vul"] = p.PluginId
						Element["request"] = scanresult.ReqMsg[0]   //base64.StdEncoding.EncodeToString([]byte())
						Element["response"] = scanresult.RespMsg[0] //base64.StdEncoding.EncodeToString([]byte())
						Element["deail"] = scanresult.Output
						Element["url"] = scanresult.Target
						Element["vul_level"] = scanresult.VulnerableLevel
						Element["result_id"] = Result_id
						if data.IsSocket {
							(*data.Msg) <- Element
						}
					}
				}

			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	p.Ctx = &ctx
	p.Cancel = &cancel
}

type PluginCallback func(args interface{}) (*util.ScanResult, bool, error)

func (p *Plugin) Run(args PluginOption) error {
	defer args.PluginWg.Done()
	defer p.Pool.Release()
	var err error
	IsSocket := args.IsSocket
	for type_name, urlinters := range args.Data {
		ur := urlinters.([]interface{})
		// fmt.Println(len(urlinters))
		p.threadwg.Add(len(ur))
		if !args.IsAllUrlsEval {
			for _, urlinter := range ur {
				go func(type_name string, urlinter map[string]interface{}) {
					data := GroupData{
						GroupType:    type_name,
						Url:          urlinter,
						Spider:       p.Spider,
						Pctx:         p.Ctx,
						Pcancel:      p.Cancel,
						IsSocket:     IsSocket,
						Msg:          args.SingelMsg,
						HttpsCert:    args.HttpsCert,
						HttpsCertKey: args.HttpsCertKey,
						Config:       args.Config,
						Rate:         args.Rate,
					}
					err = p.Pool.Invoke(data)
					if err != nil {
						logger.Debug(err.Error())
					}
				}(type_name, urlinter.(map[string]interface{}))
			}
		} else {
			go func(type_name string, ur []interface{}) {
				data := GroupData{
					GroupType:    type_name,
					GroupUrls:    ur,
					Spider:       p.Spider,
					Pctx:         p.Ctx,
					Pcancel:      p.Cancel,
					IsSocket:     IsSocket,
					Msg:          args.SingelMsg,
					HttpsCert:    args.HttpsCert,
					HttpsCertKey: args.HttpsCertKey,
					Config:       args.Config,
				}
				err = p.Pool.Invoke(data)
				if err != nil {
					logger.Debug(err.Error())
				}
			}(type_name, ur)
		}

		p.threadwg.Wait()
	}

	// if p.Spider != nil {
	// 	p.Spider.Close()
	// 	p.Spider = nil
	// }

	//logger.Info("Plugin %s has Finished!", p.PluginName)
	if args.IsSocket {
		Element := make(map[string]interface{})
		Element["status"] = 1
		//logger.Info("Plugin RLocker")

		// lock.RLock()
		Progress := *args.Progress
		*args.Progress = Progress + args.Totalprog
		// lock.RUnlock()
		// logger.Info("Plugin RUnlock")

		Element["progress"] = *args.Progress
		(*args.SingelMsg) <- Element
	}

	return err
}
