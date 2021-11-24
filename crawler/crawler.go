package crawler

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"wenscan/log"
	model2 "wenscan/model"
	"wenscan/util"

	color "github.com/logrusorgru/aurora"

	//log "wenscan/log"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/fetch"
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
	level = 3 //网页抓取深度页数

	sethreftarget = `atags = document.getElementsByTagName('a');for(i=0;i<=atags.length;i++) { if(atags[i]){atags[i].setAttribute('target', '')}}`
)

type GroupsType string

const (
	GroupsButton GroupsType = "Button"
	GroupsNormal GroupsType = "Normal"
	GroupsEmtry  GroupsType = ""
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

type Eventchanel struct {
	GroupsId       string    //针对爬虫的时候触发某个js事件因此触发其他Url请求，使用此ID作为同一群组的标识符
	ButtonCheckUrl chan bool //Button按钮的上下文
	SubmitCheckUrl chan bool //Submit按钮的上下文
	ButtonRep      chan string
	SubmitRep      chan string
	EventInfo      map[string]bool
	exit           chan int
}

type Tab struct {
	Ctx          *context.Context
	Cancel       context.CancelFunc
	NavigateReq  model2.Request
	ExtraHeaders map[string]interface{}
	ResultList   []*model2.Request
	Eventchanel  Eventchanel
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
	tab.formSubmitWG.Add(2)
	// tab.loadedWG.Add(3)
	// tab.removeLis.Add(1)

	fmt.Println(color.Green("formSubmit start"))
	go tab.CommitBySubmit()
	go tab.clickAllButton()
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
		// fmt.Println(color.Yellow(reflect.TypeOf(ev)))
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
				if FilterKey(ev.Request.URL, ForbidenKey) ||
					ev.Request.URL == tab.NavigateReq.URL.String() ||
					ev.ResourceType == network.ResourceTypeXHR {
					//XHR 允许AJAX 代码更新请求，因为它不刷新页面,有可能只刷新dom节点
					a = fetch.ContinueRequest(ev.RequestID)
				} else {
					log.Debug("FailRequest:", ev.Request.URL)
					c := chromedp.FromContext(ctx)
					ctx = cdp.WithExecutor(ctx, c.Target)
					a = fetch.FailRequest(ev.RequestID, network.ErrorReasonAborted)
				}
				var req model2.Request
				u, _ := url.Parse(ev.Request.URL)
				req.URL = &model2.URL{*u}
				req.Method = ev.Request.Method
				req.Headers = map[string]interface{}{}
				req.PostData = ev.Request.PostData

				req.Headers = ev.Request.Headers
				// 修正Referer
				req.Headers["Referer"] = ev.Request.Headers["Referer"]
				req.Source = string(ev.ResourceType)

				if !FilterKey(req.URL.String(), ForbidenKey) {
					if b, ok := tab.Eventchanel.EventInfo["Button"]; ok {
						if b {
							tab.Eventchanel.GroupsId =
								fmt.Sprintf("ButtonDoM-%s", util.RandLetterNumbers(5))
							req.GroupsId =
								tab.Eventchanel.GroupsId
						} else {
							req.GroupsId =
								tab.Eventchanel.GroupsId
						}
					}
					if b, ok := tab.Eventchanel.EventInfo["Submit"]; ok {
						if b {
							tab.Eventchanel.GroupsId =
								fmt.Sprintf("SubmitDoM-%s", util.RandLetterNumbers(5))
							req.GroupsId =
								tab.Eventchanel.GroupsId
						} else {
							req.GroupsId =
								tab.Eventchanel.GroupsId
						}
					} else {
						req.GroupsId = "Normal"
					}
					fmt.Println(color.Red(req.URL.String()))
					tab.AddResultRequest(req)
				}
				if err := chromedp.Run(ctx, a); err != nil {
					log.Error("ListenTarget error %s", err.Error())
				}
			}(*tab.Ctx, ev)
		case *page.EventJavascriptDialogOpening:
			// log.Println("EventJavascriptDialogOpening url:", ev.URL)
			tab.WG.Add(1)
			go tab.dismissDialog()
		case *page.EventNavigatedWithinDocument:
			// log.Println("EventNavigatedWithinDocument url:", ev.URL)
		case *page.EventFrameStoppedLoading:

		case *page.EventWindowOpen:
			// log.Println("EventWindowOpen url:", ev.URL)
			var req model2.Request
			u, _ := url.Parse(ev.URL)
			req.URL = &model2.URL{*u}
			req.Method = "GET"
			req.Headers = map[string]interface{}{}
			if !FilterKey(req.URL.String(), ForbidenKey) {
				if !funk.Contains(tab.NavigateReq.URL.String(), req.URL.String()) {
					tab.AddResultRequest(req)
					// log.Println("EventWindowOpen Add crawer url:", req)
				} else {
					//log.Println("The url is exist:", req)
				}
			}
		case *page.EventDocumentOpened:
			// log.Println("EventDocumentOpened url:", ev.Frame.URL)
		case *network.EventRequestWillBeSentExtraInfo:
		case *network.EventResponseReceived:
			if ev.Type == "XHR" {

			}
		case *network.EventRequestWillBeSent:
			//fmt.Println(color.Sprintf("EventRequestWillBeSent==>  url: %s requestid: %s", color.Red(ev.Request.URL), color.Red(ev.RequestID)))
			//重定向

			request := ev

			if ev.RedirectResponse != nil {
				//url = request.DocumentURL
				log.Debug("链接 %s: 重定向到: %s\n", request.RedirectResponse.URL, request.DocumentURL)
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
			log.Debug("开始请求的导航 FrameID:%s url %s , 导航类型 type: %s  导航请求理由：%s ",
				ev.FrameID, ev.URL, ev.Disposition, ev.Reason)
		}

	})
}

func InitSpider(
	ChromiumPath string,
	IncognitoContext bool,
	ExtraHeaders map[string]interface{},
	Proxy string,
	NoHeadless bool) *Spider {

	spider := Spider{}
	options := []chromedp.ExecAllocatorOption{
		chromedp.Flag("headless", NoHeadless),
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
		chromedp.Flag("proxy-server", Proxy),
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
	return &spider
}

func NewTab(spider *Spider, navigateReq model2.Request, config TabConfig) (*Tab, error) {

	var tab Tab
	spider.lock.Lock()
	ctx, cancel := chromedp.NewContext(*spider.Ctx)
	tCtx, _ := context.WithTimeout(ctx, config.TabRunTimeout)
	spider.tabs = append(spider.tabs, &tCtx)
	spider.tabCancels = append(spider.tabCancels, cancel)
	spider.lock.Unlock()
	tab.ExtraHeaders = map[string]interface{}{}
	tab.Ctx = &tCtx
	tab.Cancel = cancel
	tab.NavigateReq = navigateReq
	tab.ExtraHeaders = navigateReq.Headers
	tab.Eventchanel.EventInfo = make(map[string]bool)
	tab.Eventchanel.ButtonCheckUrl = make(chan bool)
	tab.Eventchanel.SubmitCheckUrl = make(chan bool)
	tab.Eventchanel.ButtonRep = make(chan string)
	tab.Eventchanel.SubmitRep = make(chan string)
	tab.Eventchanel.exit = make(chan int)
	tab.ListenTarget(nil)
	return &tab, nil
}

func (bro *Spider) Close() {
	fmt.Println(color.Green("closing browser."))
	for _, cancel := range bro.tabCancels {
		cancel()
	}
	for _, ctx := range bro.tabs {
		err := browser.Close().Do(*ctx)
		if err != nil {
			// fmt.Println(color.Red(err))
		}
	}
	err := browser.Close().Do(*bro.Ctx)
	if err != nil {
		// fmt.Println(color.Red(err))
	}
	(*bro.Cancel)()
}

//Crawler 爬取链接
func (tab *Tab) Crawler(extends interface{}) error {
	defer tab.Cancel()
	defer func() { tab.Eventchanel.exit <- 1 }()

	go tab.Watch()
	fmt.Println(color.Green(tab.NavigateReq.URL.String()))
	err := chromedp.Run(*tab.Ctx,
		runtime.Enable(),
		// 开启网络层API
		network.Enable(),
		// 开启请求拦截API
		fetch.Enable(),
		//设置标签头
		chromedp.ActionFunc(func(c context.Context) error {
			network.SetExtraHTTPHeaders(network.Headers(tab.ExtraHeaders)).Do(c)
			return nil
		}),
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

//CommitBySubmit 提交按钮
func (tab *Tab) CommitBySubmit() error {
	defer tab.formSubmitWG.Done()
	// 首先点击按钮 type=submit
	ctx := tab.GetExecutor()

	// 获取所有的form节点 直接执行submit
	formNodes, formErr := tab.GetNodeIDs(`form`)
	if formErr != nil || len(formNodes) == 0 {
		fmt.Println(color.Red("clickSubmit: get [form] element err"))
		if formErr != nil {
			fmt.Println(color.Red(formErr))
		}
		return formErr
	}
	tCtx1, cancel1 := context.WithTimeout(ctx, time.Second*2)
	defer cancel1()
	_ = chromedp.Submit(formNodes, chromedp.ByNodeID).Do(tCtx1)

	// 获取所有的input标签
	inputNodes, inputErr := tab.GetNodeIDs(`form input[type=submit]`)
	if inputErr != nil || len(inputNodes) == 0 {
		fmt.Println(color.Red("clickSubmit: get [form input] element err"))
		if inputErr != nil {
			fmt.Println(color.Red(inputErr))
		}
		return inputErr
	}
	tCtx2, cancel2 := context.WithTimeout(ctx, time.Second*2)
	defer cancel2()
	for _, v := range inputNodes {
		tab.Eventchanel.SubmitCheckUrl <- true
		<-tab.Eventchanel.SubmitRep
		Nodes := []cdp.NodeID{v}
		_ = chromedp.Click(Nodes, chromedp.ByNodeID).Do(tCtx2)
		//使用sleep顺序执行
		time.Sleep(time.Millisecond * 500)
		tab.Eventchanel.SubmitCheckUrl <- false
		<-tab.Eventchanel.SubmitRep
		time.Sleep(time.Millisecond * 500)

	}
	return nil
}

/**
立即根据条件获取Nodes的ID，不等待
*/
func (tab *Tab) GetNodeIDs(sel string) ([]cdp.NodeID, error) {
	ctx := tab.GetExecutor()
	return dom.QuerySelectorAll(tab.DocBodyNodeId, sel).Do(ctx)
}

//fillForm 填写表单
func (tab *Tab) fillForm() error {
	defer tab.domWG.Done()
	var InputNodes []*cdp.Node
	var TextareaNodes []*cdp.Node
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	//var res string
	//获取 input节点
	err := chromedp.Nodes("//input", &InputNodes).Do(tCtx)
	if err != nil {
		fmt.Println("fillForm error: ", err)
	}
	if len(InputNodes) == 0 {
		return errors.New("no find node")
	}

	// err = chromedp.Nodes("//textarea", &TextareaNodes).Do(tCtx)
	// if err != nil {
	// 	fmt.Println("fillForm error: ", err)
	// }
	// if len(TextareaNodes) == 0 {
	// 	return errors.New("no find node")
	// }

	InputNodes = append(TextareaNodes, InputNodes...)

	//移除input的 style 属性
	err = chromedp.Evaluate(removeAttribute, nil).Do(tCtx)
	if err != nil {
		log.Fatal("removeAttribute error: ", err)
	}

	for _, node := range InputNodes {
		var ok bool
		chromedp.EvaluateAsDevTools(fmt.Sprintf(inViewportJS, node.FullXPath()), &ok).Do(tCtx)
		if err != nil {
			// fmt.Println(color.Sprintf("inViewportJS error: %s", color.Red(err.Error())))
		}
		if !(node.AttributeValue("type") == "hidden" || node.AttributeValue("display") == "none") {
			var Jump bool
			//填写用户名
			if funk.Contains([]string{"user", "用户名", "username"}, node.AttributeValue("name")) {
				err = chromedp.SendKeys(fmt.Sprintf(`%s[name=%s]`, node.LocalName, node.AttributeValue("name")), "password").Do(tCtx)
				if err != nil {
					fmt.Println(color.Sprintf("SendKeys username error: %s", err.Error()))
					return err
				}
				Jump = true
			}
			//填写密码
			if funk.Contains([]string{"pwd", "密码", "pass", "password"}, node.AttributeValue("name")) {
				err = chromedp.SendKeys(fmt.Sprintf(`%s[name=%s]`, node.LocalName, node.AttributeValue("name")), "password").Do(tCtx)
				if err != nil {
					fmt.Println(color.Sprintf("SendKeys password error: %s", err.Error()))
					return err
				}
				Jump = true
			}

			// if funk.Contains("textarea", node.LocalName) {
			// 	err = chromedp.SendKeys(fmt.Sprintf(`%s[name=%s]`, node.LocalName, node.AttributeValue("name")), "testtextarea").Do(tCtx)
			// 	if err != nil {
			// 		fmt.Println(color.Sprintf("textarea SendKeys error: %s", err.Error()))
			// 		return err
			// 	}
			// }

			if !Jump && funk.Contains("input", node.LocalName) {
				err = chromedp.SendKeys(fmt.Sprintf(`%s[name=%s]`, node.LocalName, node.AttributeValue("name")), "test1234").Do(tCtx)
				if err != nil {
					fmt.Println(color.Sprintf("SendKeys %s %s", node.LocalName, err.Error()))
					return err
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

/**
关闭弹窗
*/
func (tab *Tab) dismissDialog() {
	defer tab.WG.Done()
	ctx := tab.GetExecutor()
	_ = page.HandleJavaScriptDialog(false).Do(ctx)
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
	req.GroupsId = "CollectLink"
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

/**
根据给的Node执行JS
*/
func (tab *Tab) EvaluateWithNode(expression string, node *cdp.Node) error {
	ctx := tab.GetExecutor()
	var res bool
	js := Snippet(expression, CashX(true), "", node)

	err := chromedp.EvaluateAsDevTools(js, &res).Do(ctx)
	if err != nil {
		return err
	}
	return nil
}

/**
click all button
*/
func (tab *Tab) clickAllButton() {
	defer tab.formSubmitWG.Done()

	// 获取所有的form中的button节点
	ctx := tab.GetExecutor()
	var ButtonNodes []*cdp.Node
	bErr := chromedp.Nodes("//button", &ButtonNodes).Do(ctx)
	if bErr != nil || len(ButtonNodes) == 0 {
		fmt.Println(color.Red("clickAllButton: get button element err"))
		if bErr != nil {
			fmt.Println(color.Red(bErr))
		}
		return
	}

	for _, node := range ButtonNodes {
		tab.Eventchanel.ButtonCheckUrl <- true
		<-tab.Eventchanel.ButtonRep
		_ = tab.EvaluateWithNode(FormNodeClickJS, node)
		//使用sleep顺序执行
		time.Sleep(time.Millisecond * 500)
		tab.Eventchanel.ButtonCheckUrl <- false
		<-tab.Eventchanel.ButtonRep
		time.Sleep(time.Millisecond * 500)
	}
	delete(tab.Eventchanel.EventInfo, "Button")
}
