package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	mapset "github.com/deckarep/golang-set"
	"gopkg.in/yaml.v2"
)

const (
	DefaultUA               = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.0 Safari/537.36"
	MaxTabsCount            = 10
	TabRunTimeout           = 20 * time.Second
	DefaultInputText        = "Crawlergo"
	FormInputKeyword        = "Crawlergo"
	SuspectURLRegex         = `(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`
	URLRegex                = `((https?|ftp|file):)?//[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]`
	AttrURLRegex            = ``
	DomContentLoadedTimeout = 5 * time.Second
	EventTriggerInterval    = 100 * time.Millisecond // 单位毫秒
	BeforeExitDelay         = 1 * time.Second
	DefaultEventTriggerMode = EventTriggerAsync
	MaxCrawlCount           = 200
)

// 请求方法
const (
	GET     = "GET"
	POST    = "POST"
	PUT     = "PUT"
	DELETE  = "DELETE"
	HEAD    = "HEAD"
	OPTIONS = "OPTIONS"
)

// 过滤模式
const (
	SimpleFilterMode = "simple"
	SmartFilterMode  = "smart"
	StrictFilterMode = "strict"
)

// 事件触发模式
const (
	EventTriggerAsync = "async"
	EventTriggerSync  = "sync"
)

// 请求的来源
const (
	FromTarget      = "Target"     //初始输入的目标
	FromNavigation  = "Navigation" //页面导航请求
	FromXHR         = "XHR"        //ajax异步请求
	FromDOM         = "DOM"        //dom解析出来的请求
	FromJSFile      = "JavaScript" //JS脚本中解析
	FromFuzz        = "PathFuzz"   //初始path fuzz
	FromRobots      = "robots.txt" //robots.txt
	FromComment     = "Comment"    //页面中的注释
	FromWebSocket   = "WebSocket"
	FromEventSource = "EventSource"
	FromFetch       = "Fetch"
	FromHistoryAPI  = "HistoryAPI"
	FromOpenWindow  = "OpenWindow"
	FromHashChange  = "HashChange"
	FromStaticRes   = "StaticResource"
	FromStaticRegex = "StaticRegex"
)

// content-type
const (
	JSON       = "application/json"
	URLENCODED = "application/x-www-form-urlencoded"
	MULTIPART  = "multipart/form-data"
)

var StaticSuffix = []string{
	"png", "gif", "jpg", "mp4", "mp3", "mng", "pct", "bmp", "jpeg", "pst", "psp", "ttf",
	"tif", "tiff", "ai", "drw", "wma", "ogg", "wav", "ra", "aac", "mid", "au", "aiff",
	"dxf", "eps", "ps", "svg", "3gp", "asf", "asx", "avi", "mov", "mpg", "qt", "rm",
	"wmv", "m4a", "bin", "xls", "xlsx", "ppt", "pptx", "doc", "docx", "odt", "ods", "odg",
	"odp", "exe", "zip", "rar", "tar", "gz", "iso", "rss", "pdf", "txt", "dll", "ico",
	"gz2", "apk", "crt", "woff", "map", "woff2", "webp", "less", "dmg", "bz2", "otf", "swf",
	"flv", "mpeg", "dat", "xsl", "csv", "cab", "exif", "wps", "m4v", "rmvb",
}
var StaticSuffixSet mapset.Set

var ScriptSuffix = []string{
	"php", "asp", "jsp", "asa",
}

var DefaultIgnoreKeywords = []string{"logout", "quit", "exit"}
var AllowedFormName = []string{"default", "mail", "code", "phone", "username", "password", "qq", "id_card", "url", "date", "number"}

type ContinueResourceList []string

var InputTextMap = map[string]map[string]interface{}{
	"mail": {
		"keyword": []string{"mail"},
		"value":   "crawlergo@gmail.com",
	},
	"code": {
		"keyword": []string{"yanzhengma", "code", "ver", "captcha"},
		"value":   "123a",
	},
	"phone": {
		"keyword": []string{"phone", "number", "tel", "shouji"},
		"value":   "18812345678",
	},
	"username": {
		"keyword": []string{"name", "user", "id", "login", "account"},
		"value":   "crawlergo@gmail.com",
	},
	"password": {
		"keyword": []string{"pass", "pwd"},
		"value":   "Crawlergo6.",
	},
	"qq": {
		"keyword": []string{"qq", "wechat", "tencent", "weixin"},
		"value":   "123456789",
	},
	"IDCard": {
		"keyword": []string{"card", "shenfen"},
		"value":   "511702197409284963",
	},
	"url": {
		"keyword": []string{"url", "site", "web", "blog", "link"},
		"value":   "https://crawlergo.nice.cn/",
	},
	"date": {
		"keyword": []string{"date", "time", "year", "now"},
		"value":   "2018-01-01",
	},
	"number": {
		"keyword": []string{"day", "age", "num", "count"},
		"value":   "10",
	},
}

type TaskYamlConfig struct {
	MaxCrawlCount           int                    `yaml:"MaxCrawlCount"` // 最大爬取的数量
	FilterMode              string                 `yaml:"FilterMode"`    // simple、smart、strict
	DBName                  string                 `yaml:"DBName"`        //数据库名
	DBUser                  string                 `yaml:"DBUser"`        //数据库用户名
	DBPassWord              string                 `yaml:"DBPassWord"`    //数据库密码
	ExtraHeaders            map[string]interface{} `yaml:"ExtraHeaders"`
	ExtraHeadersString      string                 `yaml:"ExtraHeadersString"`
	AllDomainReturn         bool                   `yaml:"AllDomainReturn"`  // 全部域名收集
	SubDomainReturn         bool                   `yaml:"SubDomainReturn"`  // 子域名收集
	IncognitoContext        bool                   `yaml:"IncognitoContext"` // 开启隐身模式
	NoHeadless              bool                   `yaml:"NoHeadless"`       // headless模式
	DomContentLoadedTimeout time.Duration          `yaml:"DomContentLoadedTimeout"`
	TabRunTimeout           time.Duration          `yaml:"TabRunTimeout"`           // 单个标签页超时
	PathByFuzz              bool                   `yaml:"PathByFuzz"`              // 通过字典进行Path Fuzz
	FuzzDictPath            string                 `yaml:"FuzzDictPath"`            // Fuzz目录字典
	PathFromRobots          bool                   `yaml:"PathFromRobots"`          // 解析Robots文件找出路径
	MaxTabsCount            int                    `yaml:"MaxTabsCount"`            // 允许开启的最大标签页数量 即同时爬取的数量
	ChromiumPath            string                 `yaml:"ChromiumPath"`            // Chromium的程序路径  `/home/zhusiyu1/chrome-linux/chrome`
	EventTriggerMode        string                 `yaml:"EventTriggerMode"`        // 事件触发的调用方式： 异步 或 顺序
	EventTriggerInterval    time.Duration          `yaml:"EventTriggerInterval"`    // 事件触发的间隔
	BeforeExitDelay         time.Duration          `yaml:"BeforeExitDelay"`         // 退出前的等待时间，等待DOM渲染，等待XHR发出捕获
	EncodeURLWithCharset    bool                   `yaml:"EncodeURLWithCharset"`    // 使用检测到的字符集自动编码URL
	IgnoreKeywords          []string               `yaml:"IgnoreKeywords"`          // 忽略的关键字，匹配上之后将不再扫描且不发送请求
	Proxy                   string                 `yaml:"Proxy"`                   // 请求代理
	CustomFormValues        map[string]interface{} `yaml:"CustomFormValues"`        // 自定义表单填充参数
	CustomFormKeywordValues map[string]interface{} `yaml:"CustomFormKeywordValues"` // 自定义表单关键词填充内容
	XssPayloads             map[string]interface{} `yaml:"XssPayloads"`             // 自定义xss的payload数据
	InstallDb               bool                   `yaml:"InstallDb"`
	EnableCrawler           bool                   `yaml:"EnableCrawler"`
	ProxyPort               int64                  `yaml:"ProxyPort"`
	Qps                     uint                   `yaml:"Qps"`
	//
}

type TaskJsonConfig struct {
	Exweb_scan_param  Exweb_scan_param    `json:"exweb_scan_param"`
	Exweb_target_info []Exweb_target_info `json:"exweb_target_info"`
	Exweb_task_info   Exweb_task_info     `json:"exweb_task_info"`
}

type Exweb_target_info struct {
	Scan_target  json.Number `json:"scan_target"`
	Target_id    json.Number `json:"target_id"`
	Target_order json.Number `json:"target_order"`
	Task_id      json.Number `json:"task_id"`
}

type Exweb_task_info struct {
	Create_time string      `json:"create_time"`
	End_time    string      `json:"end_time"`
	Scan_time   string      `json:"scan_time"`
	Start_time  string      `json:"start_time"`
	Task_id     json.Number `json:"task_id"`
	Task_name   string      `json:"task_name"`
}

type Exweb_scan_param struct {
	Anti_chain_platform   string      `json:"anti_chain_platform"`
	Api_token             string      `json:"api_token"`
	Cookie                string      `json:"cookie"`
	Domain_identificate   string      `json:"domain_identificate"`
	Forbit_domain         string      `json:"forbit_domain"`
	Forbit_path           string      `json:"forbit_path"`
	Forbit_port           string      `json:"forbit_port"`
	Http_proxy            string      `json:"http_proxy"`
	Http_response_timeout json.Number `json:"http_response_timeout"`
	Max_redirect_times    json.Number `json:"max_redirect_times"`
	Qps                   json.Number `json:"qps"`
	Max_wait_request      json.Number `json:"max_wait_request"`
	Param_model_id        json.Number `json:"param_model_id"`
	Plugin_thread_num     json.Number `json:"plugin_thread_num"`
	Rsponse_size          json.Number `json:"response_size"`
	Scan_depth            json.Number `json:"scan_depth"`
	Task_id               json.Number `json:"task_id"`
	Tcp_conn_timeout      json.Number `json:"tcp_conn_timeout"`
	User_agent            string      `json:"user_agent"`
	Web_param_id          json.Number `json:"web_param_id"`
}

//数据库配置203
const (
	UserName = "newitop"
	Password = "rjjsoft+0591"
	Ip       = "127.0.0.1"
	Port     = "3306"
	DbName   = "itop"
)

type SqlInject struct {
	Attacktype     string   `yaml:"attacktype"`
	Attackpayloads []string `yaml:"attackpayloads"`
}

func ReadResultConf(file string) (map[string]interface{}, error) {
	jsonFile, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	// FileJsonUrls := make(map[string]interface{})
	// err = json.Unmarshal([]byte(byteValue), data)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	var personFromJSON interface{}

	decoder := json.NewDecoder(bytes.NewReader(byteValue))
	decoder.UseNumber()
	decoder.Decode(&personFromJSON)

	r := personFromJSON.(map[string]interface{})

	return r, err
}

func ReadTaskConf(file string, TaskConfig *TaskYamlConfig) error {
	YamlFile, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer YamlFile.Close()
	byteValue, _ := ioutil.ReadAll(YamlFile)
	// FileJsonUrls := make(map[string]interface{})
	err = yaml.Unmarshal([]byte(byteValue), TaskConfig)
	if err != nil {
		fmt.Println(err)
	}
	return err
}
