package crawler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	model2 "wenscan/model"

	color "github.com/logrusorgru/aurora"

	//log "wenscan/Log"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/thoas/go-funk"
)

var removeAttribute = `var itags = document.getElementsByTagName('input');for(i=0;i<=itags.length;i++){if(itags[i]){itags[i].removeAttribute('style')}}`

const (
	inViewportJS = `(function(a) {
		var r = a[0].getBoundingClientRect();
		return r.top >= 0 && r.left >= 0 && r.bottom <= window.innerHeight && r.right <= window.innerWidth;
	})($x('%s'))`
	level         = 3 //网页抓取深度页数
	sethreftarget = `atags = document.getElementsByTagName('a');for(i=0;i<=atags.length;i++) { if(atags[i]){atags[i].setAttribute('target', '')}}`
)

// type chromecontext struct {
// 	Ctx      context.Context
// 	Cancel   context.CancelFunc
// 	Requests []reqinfo
// }

type Filter struct {
	MarkedQueryMap    map[string]interface{}
	QueryKeysId       string
	QueryMapId        string
	MarkedPostDataMap map[string]interface{}
	PostDataId        string
	MarkedPath        string
	PathId            string
	UniqueId          string
}

type Options struct {
	Headers  map[string]interface{}
	PostData string
}

//Spider 爬虫资源
type Spider struct {
	Ctx          *context.Context
	Cancel       *context.CancelFunc
	tabs         []*context.Context
	tabCancels   []context.CancelFunc
	ExtraHeaders map[string]interface{}
	lock         sync.Mutex
}

type Tab struct {
	Ctx          *context.Context
	Cancel       context.CancelFunc
	NavigateReq  model2.Request
	ExtraHeaders map[string]interface{}
	ResultList   []*model2.Request
	// TopFrameId       string
	// LoaderID         string
	// NavNetworkID     string
	// PageCharset      string
	// PageBindings     map[string]interface{}
	// NavDone          chan int
	// FoundRedirection bool
	DocBodyNodeId cdp.NodeID
	config        TabConfig

	lock sync.Mutex

	WG            sync.WaitGroup //当前Tab页的等待同步计数
	collectLinkWG sync.WaitGroup
	loadedWG      sync.WaitGroup //Loaded之后的等待计数
	formSubmitWG  sync.WaitGroup //表单提交完毕的等待计数
	removeLis     sync.WaitGroup //移除事件监听
	domWG         sync.WaitGroup //DOMContentLoaded 的等待计数
	fillFormWG    sync.WaitGroup //填充表单任务
}

type TabConfig struct {
	TabRunTimeout           time.Duration
	DomContentLoadedTimeout time.Duration
	EventTriggerMode        string        // 事件触发的调用方式： 异步 或 顺序
	EventTriggerInterval    time.Duration // 事件触发的间隔 单位毫秒
	BeforeExitDelay         time.Duration // 退出前的等待时间，等待DOM渲染，等待XHR发出捕获
	EncodeURLWithCharset    bool
	IgnoreKeywords          []string //
	Proxy                   string
	CustomFormValues        map[string]string
	CustomFormKeywordValues map[string]string
}

/**
获取当前标签页CDP的执行上下文
*/
func (tab *Tab) GetExecutor() context.Context {
	c := chromedp.FromContext(*tab.Ctx)
	ctx := cdp.WithExecutor(*tab.Ctx, c.Target)
	return ctx
}

/**
处理 401 407 认证弹窗
*/
func (tab *Tab) HandleAuthRequired(req *fetch.EventAuthRequired) {
	defer tab.WG.Done()
	fmt.Println(color.Yellow("auth required found, auto auth."))

	ctx := tab.GetExecutor()
	authRes := fetch.AuthChallengeResponse{
		Response: fetch.AuthChallengeResponseResponseProvideCredentials,
		Username: "admin",
		Password: "admin",
	}
	// 取消认证
	_ = fetch.ContinueWithAuth(req.RequestID, &authRes).Do(ctx)
}

/**
获取的Body的NodeId 用于之后子节点无等待查询
最多等待3秒 如果DOM依旧没有渲染完成，则退出
*/
func (tab *Tab) getBodyNodeId() bool {
	var docNodeIDs []cdp.NodeID
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()
	err := chromedp.WaitReady(`body`, chromedp.ByQuery).Do(tCtx)
	if err != nil {
		fmt.Println(color.Red("getBodyNodeId WaitReady failed, maybe DOM not ready?"))
		fmt.Println(color.Red(err))
		return false
	}
	// 获取 Frame document root
	err = chromedp.NodeIDs(`body`, &docNodeIDs, chromedp.ByQuery).Do(tCtx)
	if len(docNodeIDs) == 0 || err != nil {
		// not root node yet?
		fmt.Println(color.Red("getBodyNodeId failed, maybe DOM not ready?"))
		if err != nil {
			fmt.Println(color.Red(err))
		}
		return false
	}
	tab.DocBodyNodeId = docNodeIDs[0]
	return true
}

/**
在DOMContentLoaded完成后执行
*/
func (tab *Tab) AfterDOMRun() {
	defer tab.WG.Done()
	fmt.Println(color.Green("afterDOMRun start"))
	// 获取当前body节点的nodeId 用于之后查找子节点
	if !tab.getBodyNodeId() {
		fmt.Println(color.Red("no body document NodeID, exit."))
		return
	}
	//填充表单
	tab.domWG.Add(1)
	fmt.Println(color.Magenta("The Function tab.fillForm() is call"))
	go tab.fillForm()
	tab.domWG.Wait()
	fmt.Println(color.Green("afterDOMRun end"))
	tab.WG.Add(1)
	go tab.AfterLoadedRun()
}

/**
在页面Loaded之后执行
同时等待 afterDOMRun 之后执行
*/
func (tab *Tab) AfterLoadedRun() {
	defer tab.WG.Done()
	fmt.Println(color.Green("afterLoadedRun start"))
	tab.formSubmitWG.Add(1)
	// tab.loadedWG.Add(3)
	// tab.removeLis.Add(1)
	fmt.Println(color.Green("formSubmit start"))
	go tab.CommitBybutton()
	tab.formSubmitWG.Wait()
	fmt.Println(color.Green("formSubmit end"))

	// if tab.config.EventTriggerMode == config.EventTriggerAsync {
	// 	go tab.triggerJavascriptProtocol()
	// 	go tab.triggerInlineEvents()
	// 	go tab.triggerDom2Events()
	// 	tab.loadedWG.Wait()
	// } else if tab.config.EventTriggerMode == config.EventTriggerSync {
	// 	tab.triggerInlineEvents()
	// 	time.Sleep(tab.config.EventTriggerInterval)
	// 	tab.triggerDom2Events()
	// 	time.Sleep(tab.config.EventTriggerInterval)
	// 	tab.triggerJavascriptProtocol()
	// }

	// 事件触发之后 需要等待一点时间让浏览器成功发出ajax请求 更新DOM
	time.Sleep(2 * time.Second)

	// go tab.RemoveDOMListener()
	// tab.removeLis.Wait()
	fmt.Println(color.Green("afterLoadedRun end"))
}

//ListenTarget
func (tab *Tab) ListenTarget(extends interface{}) {
	var DOMContentLoadedRun = false
	chromedp.ListenTarget(*tab.Ctx, func(ev interface{}) {
		Response := make(map[string]string)
		Responses := []map[string]string{}
		// fmt.Println(reflect.TypeOf(ev))
		switch ev := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			for _, arg := range ev.Args {
				fmt.Printf("%s - %s\n", arg.Type, string(arg.Value))
				Response[string(ev.Type)] = strings.ReplaceAll(string(arg.Value), "\"", "")
				Responses = append(Responses, Response)
			}
		case *runtime.EventExceptionThrown:
		case *fetch.EventRequestPaused:
			go func(ctx context.Context, ev *fetch.EventRequestPaused) {
				var a chromedp.Action
				if strings.HasSuffix(ev.Request.URL, ".css") ||
					strings.HasSuffix(ev.Request.URL, ".js") ||
					strings.HasSuffix(ev.Request.URL, ".ico") ||
					strings.HasSuffix(ev.Request.URL, "#") ||
					funk.Contains(ev.Request.URL, "js?") ||
					funk.Contains(ev.Request.URL, "css?") ||
					funk.Contains(ev.Request.URL, "woff2?") ||
					funk.Contains(ev.Request.URL, "woff?") ||
					funk.Contains(ev.Request.URL, tab.NavigateReq.URL.String()) {
					// fmt.Println("request:", ev.Request.URL)
					a = fetch.ContinueRequest(ev.RequestID)
				} else {
					fmt.Println("FailRequest:", ev.Request.URL)
					c := chromedp.FromContext(ctx)
					ctx = cdp.WithExecutor(ctx, c.Target)
					a = fetch.FailRequest(ev.RequestID, network.ErrorReasonAborted)
				}
				var req model2.Request
				u, _ := url.Parse(ev.Request.URL)
				req.URL = &model2.URL{*u}
				req.Method = ev.Request.Method
				if !strings.HasSuffix(ev.Request.URL, ".css") &&
					!strings.HasSuffix(ev.Request.URL, ".js") &&
					!strings.HasSuffix(ev.Request.URL, ".ico") &&
					!strings.HasSuffix(ev.Request.URL, "#") &&
					!funk.Contains(ev.Request.URL, "js?") &&
					!funk.Contains(ev.Request.URL, "css?") &&
					!funk.Contains(ev.Request.URL, "woff2?") &&
					!funk.Contains(ev.Request.URL, "woff?") {
					if !funk.Contains(tab.NavigateReq.URL.String(), req.URL.String()) {
						tab.AddResultRequest(req)
						// log.Println("Add crawer url:", req)
					} else {
						//log.Println("The url is exist:", req)
					}
				}
				if err := chromedp.Run(ctx, a); err != nil {
					log.Println("ListenTarget error", err)
				}
			}(*tab.Ctx, ev)
		case *page.EventJavascriptDialogOpening:
			log.Println("EventJavascriptDialogOpening url:", ev.URL)
		case *page.EventNavigatedWithinDocument:
			log.Println("EventNavigatedWithinDocument url:", ev.URL)
		case *page.EventWindowOpen:
			log.Println("EventWindowOpen url:", ev.URL)
			var req model2.Request
			u, _ := url.Parse(ev.URL)
			req.URL = &model2.URL{*u}
			req.Method = "GET"
			if !strings.HasSuffix(ev.URL, ".css") &&
				!strings.HasSuffix(ev.URL, ".js") &&
				!strings.HasSuffix(ev.URL, ".ico") &&
				!funk.Contains(ev.URL, "js?") &&
				!funk.Contains(ev.URL, "css?") &&
				!funk.Contains(ev.URL, "woff2?") &&
				!funk.Contains(ev.URL, "woff?") {
				if !funk.Contains(tab.NavigateReq.URL.String(), req.URL.String()) {
					tab.AddResultRequest(req)
					// tab.ResultList = append(tab.ResultList, &req)
					log.Println("EventWindowOpen Add crawer url:", req)
				} else {
					//log.Println("The url is exist:", req)
				}
			}
		case *page.EventDocumentOpened:
			log.Println("EventDocumentOpened url:", ev.Frame.URL)
		case *network.EventRequestWillBeSentExtraInfo:
		case *network.EventRequestWillBeSent:
			//重定向
			request := ev
			if ev.RedirectResponse != nil {
				//url = request.DocumentURL
				fmt.Printf("链接 %s: 重定向到: %s\n", request.RedirectResponse.URL, request.DocumentURL)
			}
		case *page.EventDomContentEventFired:
			if DOMContentLoadedRun {
				return
			}
			DOMContentLoadedRun = true
			tab.WG.Add(1)
			go tab.AfterDOMRun()
		case *page.EventLoadEventFired:
			if DOMContentLoadedRun {
				return
			}
			DOMContentLoadedRun = true
			tab.WG.Add(1)
			go tab.AfterDOMRun()
		case *page.EventFrameRequestedNavigation:
			// log.Printf("开始请求的导航 FrameID:%s url %s , 导航类型 type: %s  导航请求理由：%s ",
			// 	ev.FrameID, ev.URL, ev.Disposition, ev.Reason)

		}

	})
}

func (spider *Spider) Init() {
	options := []chromedp.ExecAllocatorOption{
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-images", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-xss-auditor", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("allow-running-insecure-content", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-webgl", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("block-new-web-contents", true),
		chromedp.Flag("blink-settings", "imagesEnabled=false"),
		chromedp.UserAgent(`Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36`),
	}
	ExecAllocator := append(chromedp.DefaultExecAllocatorOptions[:], options...)
	//NewExecAllocator 是新建一个浏览器
	ctx, Cancel := chromedp.NewExecAllocator(context.Background(), ExecAllocator...)
	lctx, Cancel := chromedp.NewContext(ctx,
		chromedp.WithLogf(log.Printf),
	)
	chromedp.Run(lctx)
	spider.Ctx = &lctx
	spider.Cancel = &Cancel
}

func (spider *Spider) NewTab(timeout time.Duration) (*context.Context, context.CancelFunc) {
	spider.lock.Lock()
	ctx, cancel := chromedp.NewContext(*spider.Ctx)
	tCtx, _ := context.WithTimeout(ctx, timeout)
	spider.tabs = append(spider.tabs, &tCtx)
	spider.tabCancels = append(spider.tabCancels, cancel)
	spider.lock.Unlock()
	return &tCtx, cancel
}

func (bro *Spider) Close() {
	fmt.Println(color.Green("closing browser."))
	for _, cancel := range bro.tabCancels {
		cancel()
	}
	for _, ctx := range bro.tabs {
		err := browser.Close().Do(*ctx)
		if err != nil {
			fmt.Println(color.Red(err))
		}
	}
	err := browser.Close().Do(*bro.Ctx)
	if err != nil {
		fmt.Println(color.Red(err))
	}
	(*bro.Cancel)()
}

func NewTabaObject(spider *Spider, navigateReq model2.Request) (*Tab, error) {
	var tab Tab
	tab.ExtraHeaders = map[string]interface{}{}
	tab.Ctx, tab.Cancel = spider.NewTab(20 * time.Second)
	tab.NavigateReq = navigateReq
	tab.ListenTarget(nil)
	return &tab, nil
}

//Crawler 爬取链接
func (tab *Tab) Crawler(extends interface{}) error {
	defer tab.Cancel()
	fmt.Println(color.Green(tab.NavigateReq.URL.String()))
	err := chromedp.Run(*tab.Ctx,
		runtime.Enable(),
		// 开启网络层API
		network.Enable(),
		// 开启请求拦截API
		fetch.Enable(),
		// 开启导航
		chromedp.Navigate(tab.NavigateReq.URL.String()),
	)
	if err != nil {
		return err
	}
	//等待DOM更新结束
	// go func() {
	// 	// 等待所有协程任务结束
	// 	tab.WG.Wait()
	// 	// tab.NavDone <- 1
	// }()

	tab.WG.Wait()

	fmt.Println(color.Green("collectLinks start"))
	tab.collectLinkWG.Add(3)
	go tab.CollectLink()
	tab.collectLinkWG.Wait()
	fmt.Println(color.Green("collectLinks end"))

	return nil
}

//PrintHtml 打印当前html
func PrintHtml(ctx context.Context) error {
	var html string
	err := chromedp.OuterHTML("body", &html, chromedp.BySearch).Do(ctx)
	if err != nil {
		log.Println("PrintHtml error:", err.Error())
	}
	fmt.Println(html)
	return err
}

//CommitBybutton 提交按钮
func (tab *Tab) CommitBybutton() error {
	defer tab.formSubmitWG.Done()
	var nodes []*cdp.Node
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	err := chromedp.Nodes("//input[@type='submit']", &nodes, chromedp.BySearch).Do(tCtx)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		log.Printf("no find //input[@type='submit'] node")
		return nil
	}
	for _, node := range nodes {
		if !(node.AttributeValue("type") == "hidden" || node.AttributeValue("display") == "none") {
			//鼠标移动到button上
			err := chromedp.MouseClickNode(node, chromedp.ButtonType(input.Left)).Do(tCtx)
			if err != nil {
				//log.Println("CommitBybutton MouseClickNode error:", err)
			}
			chromedp.Sleep(1 * time.Second)
		}
	}
	return nil
}

//fillForm 填写表单
func (tab *Tab) fillForm() error {
	defer tab.domWG.Done()
	var nodes []*cdp.Node
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	//var res string
	//获取 input节点
	err := chromedp.Nodes("//input", &nodes).Do(tCtx)
	if err != nil {
		fmt.Println("fillForm error: ", err)
	}
	if len(nodes) == 0 {
		return errors.New("no find node")
	}
	//移除input的 style 属性
	err = chromedp.Evaluate(removeAttribute, nil).Do(tCtx)
	if err != nil {
		log.Fatal("removeAttribute error: ", err)
	}

	for _, node := range nodes {
		var ok bool
		chromedp.EvaluateAsDevTools(fmt.Sprintf(inViewportJS, node.FullXPath()), &ok).Do(tCtx)
		if err != nil {
			log.Fatal("got  error:", err)
		}
		if !(node.AttributeValue("type") == "hidden" || node.AttributeValue("display") == "none") {
			//fmt.Println(node.Attributes)
			//填写用户名
			for _, name := range []string{"user", "用户名", "username"} {
				if v := node.AttributeValue("name"); name == v {
					err = chromedp.SendKeys(fmt.Sprintf(`input[name=%s]`, v), "craw").Do(tCtx)
					if err != nil {
						log.Fatal("SendKeys user name error:", err)
					}
				}
			}
			//填写密码
			for _, name := range []string{"pwd", "密码", "pass", "password"} {
				if v := node.AttributeValue("name"); name == v {
					err = chromedp.SendKeys(fmt.Sprintf(`input[name=%s]`, v), "password").Do(tCtx)
					if err != nil {
						log.Fatal("SendKeys password error:", err)
					}
				}
			}

		}

	}
	return err
}

//CollectLink 收集链接
func (tab *Tab) CollectLink() error {
	go tab.collectHrefLinks()
	go tab.collectObjectLinks()
	go tab.collectCommentLinks()
	return nil
}

func (tab *Tab) collectHrefLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()
	// 收集 src href data-url 属性值
	attrNameList := []string{"src", "href", "data-url", "data-href"}
	for _, attrName := range attrNameList {
		tCtx, cancel := context.WithTimeout(ctx, time.Second*1)
		var attrs []map[string]string
		_ = chromedp.AttributesAll(fmt.Sprintf(`[%s]`, attrName), &attrs, chromedp.ByQueryAll).Do(tCtx)
		cancel()
		for _, attrMap := range attrs {
			tab.AddResultUrl("GET", attrMap[attrName], "DOM")
		}
	}
}

func (tab *Tab) collectObjectLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()
	// 收集 object[data] links
	tCtx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	var attrs []map[string]string
	_ = chromedp.AttributesAll(`object[data]`, &attrs, chromedp.ByQueryAll).Do(tCtx)
	for _, attrMap := range attrs {
		tab.AddResultUrl("GET", attrMap["data"], "DOM")
	}
}

func (tab *Tab) collectCommentLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()
	// 收集注释中的链接
	var nodes []*cdp.Node
	tCtxComment, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	commentErr := chromedp.Nodes(`//comment()`, &nodes, chromedp.BySearch).Do(tCtxComment)
	if commentErr != nil {
		fmt.Println(color.Red("get comment nodes err"))
		fmt.Println(color.Red(commentErr))
		return
	}
	urlRegex := regexp.MustCompile(`((https?|ftp|file):)?//[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]`)
	for _, node := range nodes {
		content := node.NodeValue
		urlList := urlRegex.FindAllString(content, -1)
		for _, url := range urlList {
			tab.AddResultUrl("GET", url, "Comment")
		}
	}
}

func (tab *Tab) AddResultUrl(method string, _url string, source string) {
	navUrl := tab.NavigateReq.URL
	url, err := model2.GetUrl(_url, *navUrl)
	if err != nil {
		return
	}
	option := model2.Options{
		Headers:  map[string]interface{}{},
		PostData: "",
	}
	referer := navUrl.String()
	// 处理Host绑定
	if host, ok := tab.NavigateReq.Headers["Host"]; ok {
		if host != navUrl.Hostname() && url.Hostname() == host {
			url, _ = model2.GetUrl(strings.Replace(url.String(), "://"+url.Hostname(), "://"+navUrl.Hostname(), -1), *navUrl)
			option.Headers["Host"] = host
			referer = strings.Replace(navUrl.String(), navUrl.Host, host.(string), -1)
		}
	}
	// 添加Cookie
	if cookie, ok := tab.NavigateReq.Headers["Cookie"]; ok {
		option.Headers["Cookie"] = cookie
	}

	// 修正Referer
	option.Headers["Referer"] = referer
	for key, value := range tab.ExtraHeaders {
		option.Headers[key] = value
	}
	req := model2.GetRequest(method, url, option)
	req.Source = source

	tab.lock.Lock()
	tab.ResultList = append(tab.ResultList, &req)
	tab.lock.Unlock()
}

func (tab *Tab) AddResultRequest(req model2.Request) {
	for key, value := range tab.ExtraHeaders {
		req.Headers[key] = value
	}
	tab.lock.Lock()
	tab.ResultList = append(tab.ResultList, &req)
	tab.lock.Unlock()
}
