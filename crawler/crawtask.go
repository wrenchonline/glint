package crawler

import (
	"sync"
	"time"
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

}
