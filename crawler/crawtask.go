package crawler

import (
	"sync"
	"time"
	"wenscan/log"
	"wenscan/model"

	"github.com/panjf2000/ants/v2"
)

type Result struct {
	ReqList       []*model.Request // 返回的同域名结果
	AllReqList    []*model.Request // 所有域名的请求
	AllDomainList []string         // 所有域名列表
	SubDomainList []string         // 子域名列表
	resultLock    sync.Mutex       // 合并结果时加锁
}

type CrawlerTask struct {
	Browser       *Spider          //
	RootDomain    string           // 当前爬取根域名 用于子域名收集
	Targets       []*model.Request // 输入目标
	Result        *Result          // 最终结果
	Config        *TaskConfig      // 配置信息
	smartFilter   SmartFilter      // 过滤对象
	Pool          *ants.Pool       // 协程池
	taskWG        sync.WaitGroup   // 等待协程池所有任务结束
	crawledCount  int              // 爬取过的数量
	taskCountLock sync.Mutex       // 已爬取的任务总数锁
}

type tabTask struct {
	crawlerTask *CrawlerTask
	browser     *Spider
	req         *model.Request
	pool        *ants.Pool
}

type TaskConfig struct {
	MaxCrawlCount           int    // 最大爬取的数量
	FilterMode              string // simple、smart、strict
	ExtraHeaders            map[string]interface{}
	ExtraHeadersString      string
	AllDomainReturn         bool // 全部域名收集
	SubDomainReturn         bool // 子域名收集
	IncognitoContext        bool // 开启隐身模式
	NoHeadless              bool // headless模式
	DomContentLoadedTimeout time.Duration
	TabRunTimeout           time.Duration          // 单个标签页超时
	PathByFuzz              bool                   // 通过字典进行Path Fuzz
	FuzzDictPath            string                 // Fuzz目录字典
	PathFromRobots          bool                   // 解析Robots文件找出路径
	MaxTabsCount            int                    // 允许开启的最大标签页数量 即同时爬取的数量
	ChromiumPath            string                 // Chromium的程序路径  `/home/zhusiyu1/chrome-linux/chrome`
	EventTriggerMode        string                 // 事件触发的调用方式： 异步 或 顺序
	EventTriggerInterval    time.Duration          // 事件触发的间隔
	BeforeExitDelay         time.Duration          // 退出前的等待时间，等待DOM渲染，等待XHR发出捕获
	EncodeURLWithCharset    bool                   // 使用检测到的字符集自动编码URL
	IgnoreKeywords          []string               // 忽略的关键字，匹配上之后将不再扫描且不发送请求
	Proxy                   string                 // 请求代理
	CustomFormValues        map[string]string      // 自定义表单填充参数
	CustomFormKeywordValues map[string]string      // 自定义表单关键词填充内容
	XssPayloads             map[string]interface{} // Xss的payload数据结构
}

/**
根据请求列表生成tabTask协程任务列表
*/
func (t *CrawlerTask) generateTabTask(req *model.Request) *tabTask {
	task := tabTask{
		crawlerTask: t,
		browser:     t.Browser,
		req:         req,
	}
	return &task
}

func (t *CrawlerTask) Run() {
	defer t.Pool.Release()  // 释放协程池
	defer t.Browser.Close() // 关闭浏览器
	if t.Config.PathFromRobots {
		reqsFromRobots := GetPathsFromRobots(*t.Targets[0])
		log.Info("get paths from robots.txt: ", len(reqsFromRobots))
		t.Targets = append(t.Targets, reqsFromRobots...)
	}
	if t.Config.FuzzDictPath != "" {
		if t.Config.PathByFuzz {
			log.Warning("`--fuzz-path` is ignored, using `--fuzz-path-dict` instead")
		}
		reqsByFuzz := GetPathsByFuzzDict(*t.Targets[0], t.Config.FuzzDictPath)
		t.Targets = append(t.Targets, reqsByFuzz...)
	} else if t.Config.PathByFuzz {
		reqsByFuzz := GetPathsByFuzz(*t.Targets[0])
		log.Info("get paths by fuzzing: ", len(reqsByFuzz))
		t.Targets = append(t.Targets, reqsByFuzz...)
	}
	t.Result.AllReqList = t.Targets[:]
	var initTasks []*model.Request

	for _, req := range t.Targets {
		if t.smartFilter.DoFilter(req) {
			log.Debug("filter req: %s", req.URL.RequestURI())
			continue
		}
		initTasks = append(initTasks, req)
		t.Result.ReqList = append(t.Result.ReqList, req)
	}
	log.Info("filter repeat, target count: ", len(initTasks))

	for _, req := range initTasks {
		if !FilterKey(req.URL.String(), t.Config.IgnoreKeywords) {
			t.addTask2Pool(req)
		}
	}

	t.taskWG.Wait()

	// 全部域名
	t.Result.AllDomainList = AllDomainCollect(t.Result.AllReqList)
	// 子域名
	t.Result.SubDomainList = SubDomainCollect(t.Result.AllReqList, t.RootDomain)
}

/**
添加任务到协程池
添加之前实时过滤
*/
func (t *CrawlerTask) addTask2Pool(req *model.Request) {
	t.taskCountLock.Lock()
	if t.crawledCount >= t.Config.MaxCrawlCount {
		t.taskCountLock.Unlock()
		return
	} else {
		t.crawledCount += 1
	}
	t.taskCountLock.Unlock()

	t.taskWG.Add(1)
	task := t.generateTabTask(req)
	go func() {
		err := t.Pool.Submit(task.Task)
		if err != nil {
			t.taskWG.Done()
			log.Error("addTask2Pool ", err)
		}
	}()
}

/**
单个运行的tab标签任务，实现了workpool的接口
*/
func (t *tabTask) Task() {
	defer t.crawlerTask.taskWG.Done()
	tab := NewTab(t.browser, *t.req, TabConfig{
		TabRunTimeout:           t.crawlerTask.Config.TabRunTimeout,
		DomContentLoadedTimeout: t.crawlerTask.Config.DomContentLoadedTimeout,
		EventTriggerMode:        t.crawlerTask.Config.EventTriggerMode,
		EventTriggerInterval:    t.crawlerTask.Config.EventTriggerInterval,
		BeforeExitDelay:         t.crawlerTask.Config.BeforeExitDelay,
		EncodeURLWithCharset:    t.crawlerTask.Config.EncodeURLWithCharset,
		IgnoreKeywords:          t.crawlerTask.Config.IgnoreKeywords,
		CustomFormValues:        t.crawlerTask.Config.CustomFormValues,
		CustomFormKeywordValues: t.crawlerTask.Config.CustomFormKeywordValues,
	})
	tab.Start()

	// 收集结果
	t.crawlerTask.Result.resultLock.Lock()
	t.crawlerTask.Result.AllReqList = append(t.crawlerTask.Result.AllReqList, tab.ResultList...)
	t.crawlerTask.Result.resultLock.Unlock()

	for _, req := range tab.ResultList {
		if t.crawlerTask.Config.FilterMode == config.SimpleFilterMode {
			if !t.crawlerTask.smartFilter.SimpleFilter.DoFilter(req) {
				t.crawlerTask.Result.resultLock.Lock()
				t.crawlerTask.Result.ReqList = append(t.crawlerTask.Result.ReqList, req)
				t.crawlerTask.Result.resultLock.Unlock()
				if !FilterKey(req.URL.String(), t.crawlerTask.Config.IgnoreKeywords) {
					t.crawlerTask.addTask2Pool(req)
				}
			}
		} else {
			if !t.crawlerTask.smartFilter.DoFilter(req) {
				t.crawlerTask.Result.resultLock.Lock()
				t.crawlerTask.Result.ReqList = append(t.crawlerTask.Result.ReqList, req)
				t.crawlerTask.Result.resultLock.Unlock()
				if !FilterKey(req.URL.String(), t.crawlerTask.Config.IgnoreKeywords) {
					t.crawlerTask.addTask2Pool(req)
				}
			}
		}
	}
}
