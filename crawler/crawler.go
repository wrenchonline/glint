package crawler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	//log "wenscan/Log"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/thoas/go-funk"
)

var hosturl = "http://localhost/"
var hostlogin = "login.php"
var hostlogout = "logout.php"
var removeAttribute = `var itags = document.getElementsByTagName('input');for(i=0;i<=itags.length;i++){if(itags[i]){itags[i].removeAttribute('style')}}`
var fetchok bool

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

type reqinfo struct {
	Method  string
	URL     string
	Hreader string
}

//Spider 爬虫资源，设计目的是爬网页，注意使用此结构的函数在多线程中没上锁是不安全的，理想状态为一条线程使用这个结构
type Spider struct {
	Parentcxt     context.Context //主context
	Requests      []reqinfo
	Scanhostpage  string
	StartPaused   bool
	ForbiddenUrl  []string
	Cookies       []chromedp.Action
	Responses     chan []map[string]string
	ReqMode       string
	ExecAllocator []func(*chromedp.ExecAllocator)
	ch            chan *dom.EventDocumentUpdated
}

// func (chromecontext *chromecontext) Close() {
// 	defer (chromecontext.Cancel)()
// 	defer chromedp.Cancel(chromecontext.Ctx)
// }

//CheckPayloadbyConsoleLog 检测回复中的log是否有我们触发的payload
func (spider *Spider) CheckPayloadbyConsole(types string, xsschecker string) bool {
	select {
	case responseS := <-spider.Responses:
		for _, response := range responseS {
			if v, ok := response[types]; ok {
				if v == xsschecker {
					return true
				}
			}
		}
	case <-time.After(time.Duration(5) * time.Second):
		return false
	}
	return false
}

//ListenTarget
func (spider *Spider) ListenTarget(ctx context.Context, extends interface{}) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		Response := make(map[string]string)
		Responses := []map[string]string{}
		// fmt.Println(reflect.TypeOf(ev))
		switch ev := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			//fmt.Printf("* console.%s call:\n", ev.Type)
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
					ev.Request.URL == spider.Scanhostpage {
					fmt.Println("request:", ev.Request.URL)
					a = fetch.ContinueRequest(ev.RequestID)
				} else {
					fmt.Println("FailRequest:", ev.Request.URL)
					c := chromedp.FromContext(ctx)
					ctx = cdp.WithExecutor(ctx, c.Target)
					a = fetch.FailRequest(ev.RequestID, network.ErrorReasonAborted)
				}
				var req reqinfo
				req.URL = ev.Request.URL
				req.Method = ev.Request.Method
				if !strings.HasSuffix(ev.Request.URL, ".css") &&
					!strings.HasSuffix(ev.Request.URL, ".js") &&
					!strings.HasSuffix(ev.Request.URL, ".ico") &&
					!strings.HasSuffix(ev.Request.URL, "#") &&
					!funk.Contains(ev.Request.URL, "js?") &&
					!funk.Contains(ev.Request.URL, "css?") &&
					!funk.Contains(ev.Request.URL, "woff2?") &&
					!funk.Contains(ev.Request.URL, "woff?") {
					if !funk.Contains(spider.Requests, req) {
						spider.Requests = append(spider.Requests, req)
						log.Println("Add crawer url:", req)
					} else {
						//log.Println("The url is exist:", req)
					}
				}
				if err := chromedp.Run(ctx, a); err != nil {
					log.Println("ListenTarget error", err)
				}
			}(ctx, ev)
		case *page.EventJavascriptDialogOpening:
			log.Println("EventJavascriptDialogOpening url:", ev.URL)
		case *page.EventNavigatedWithinDocument:
			log.Println("EventNavigatedWithinDocument url:", ev.URL)

		case *page.EventWindowOpen:
			log.Println("EventWindowOpen url:", ev.URL)
			var req reqinfo
			req.URL = ev.URL
			req.Method = "GET"
			if !strings.HasSuffix(ev.URL, ".css") &&
				!strings.HasSuffix(ev.URL, ".js") &&
				!strings.HasSuffix(ev.URL, ".ico") &&
				!funk.Contains(ev.URL, "js?") &&
				!funk.Contains(ev.URL, "css?") &&
				!funk.Contains(ev.URL, "woff2?") &&
				!funk.Contains(ev.URL, "woff?") {
				if !funk.Contains(spider.Requests, req) {
					spider.Requests = append(spider.Requests, req)
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
			//fmt.Printf(" request url: %s\n", request.DocumentURL)
			if ev.RedirectResponse != nil {
				//url = request.DocumentURL
				fmt.Printf("链接 %s: 重定向到: %s\n", request.RedirectResponse.URL, request.DocumentURL)
			}
		case *network.EventResponseReceived:
		case *network.EventResponseReceivedExtraInfo:
		case *dom.EventDocumentUpdated:
		case *page.EventLoadEventFired:
		case *page.EventFrameRequestedNavigation:
			// log.Printf("开始请求的导航 FrameID:%s url %s , 导航类型 type: %s  导航请求理由：%s ",
			// 	ev.FrameID, ev.URL, ev.Disposition, ev.Reason)
		case *page.EventFrameStoppedLoading:
		case *dom.EventSetChildNodes:
		case *page.EventLifecycleEvent:

		}

	})
}

func (spider *Spider) Init() {
	spider.Responses = make(chan []map[string]string)
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
	spider.ExecAllocator = append(chromedp.DefaultExecAllocatorOptions[:], options...)
	//NewExecAllocator 是新建一个浏览器
	c, _ := chromedp.NewExecAllocator(context.Background(), spider.ExecAllocator...)
	spider.Parentcxt = c
	spider.ch = make(chan *dom.EventDocumentUpdated, 5)
}

//Crawler 爬取链接
func (spider *Spider) Crawler(url string, function interface{}) (context.Context, context.CancelFunc, error) {
	var (
		ctx    context.Context
		cctx   context.Context
		cancel context.CancelFunc
		err    error
	)
	//新建一个标签页
	if v, ok := function.(context.Context); ok {
		c := chromedp.FromContext(v)
		cctx = cdp.WithExecutor(v, c.Target)
		ctx = cctx
		if _, ok := ctx.Deadline(); ok {
			ctx, cancel = chromedp.NewContext(spider.Parentcxt)
		}
	} else {
		ctx, cancel = chromedp.NewContext(spider.Parentcxt)
	}

	if _, ok := function.(context.Context); !ok {
		for _, Cookies := range spider.Cookies {
			//设置cookie
			err = chromedp.Run(
				ctx,
				Cookies)
		}
		spider.ListenTarget(ctx, spider.Requests)
		err = chromedp.Run(
			ctx,
			//开启拦截请求
			fetch.Enable(),
			//禁止链接禁用的url

			//导航
			chromedp.Navigate(url),
		)
		newctx, _ := context.WithTimeout(ctx, 2*time.Second)
		err = chromedp.Run(
			newctx,
			fetch.Enable(),
			spider.ChlikByLink(),
		)
		if err != nil {
			log.Println(err.Error())
		}
		nctxtimeout, _ := context.WithTimeout(ctx, 2*time.Second)
		err = chromedp.Run(

			nctxtimeout,
			//开启拦截请求
			fetch.Enable(),
			//导航
			chromedp.Navigate(url),
			// 获取获取服务列表HTML
			spider.CommitBybut(),
		)

	} else {
		//第二次请求
		ctx11, cancel := chromedp.NewContext(ctx)
		defer cancel()
		ctx11, cancel = context.WithTimeout(ctx11, 15*time.Second)
		defer cancel()
		spider.ListenTarget(ctx11, spider.Requests)
		err = chromedp.Run(
			ctx11,
			chromedp.Navigate(url),
		)
		_ctx, _cancel := context.WithTimeout(ctx11, 3*time.Second)
		defer _cancel()
		err = chromedp.Run(
			_ctx,
			fetch.Enable(),
			spider.CommitBybut(),
		)
		if err != nil {
			//log.Println(err.Error())
		}
		newctx, newcancel := context.WithTimeout(ctx11, 3*time.Second)
		defer newcancel()
		//spider.ListenTarget(newctx, spider.Requests)
		err = chromedp.Run(
			newctx,
			fetch.Enable(),
			spider.ChlikByLink(),
		)
		if err != nil {
			//log.Println(err.Error())
		}
	}

	return ctx, cancel, err
}

func (spider *Spider) ShowCookies() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		cookies, err := network.GetAllCookies().Do(ctx)
		if err != nil {
			return err
		}
		for i, cookie := range cookies {
			log.Printf("chrome cookie %d: %+v", i, cookie)
		}
		return nil
	})
}

func (spider *Spider) SetCookie(name, value, domain, path string, httpOnly, secure bool) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		expr := cdp.TimeSinceEpoch(time.Now().Add(180 * 24 * time.Hour))
		network.SetCookie(name, value).
			WithExpires(&expr).
			WithDomain(domain).
			WithPath(path).
			WithHTTPOnly(httpOnly).
			WithSecure(secure).
			Do(ctx)
		return nil
	})
}

//GetPageInfomation 获取网页信息
func (spider *Spider) GetPageInfomation() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		//var res string
		if err := chromedp.WaitReady(`body`, chromedp.ByQuery).Do(ctx); err != nil {
			return err
		}

		chromedp.WaitReady(`a`).Do(ctx)
		if err := spider.ChlikLink(ctx); err != nil {
			return err
		}
		if err := spider.CommitBybutton(ctx); err != nil {
			return err
		}
		return nil
	})
}

//CommitBybut 封装提交接口
func (spider *Spider) CommitBybut() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		//PrintHtml(ctx)
		if err := spider.CommitBybutton(ctx); err != nil {
			return err
		}
		return nil
	})
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

//ChlikByLink 封装提交链接接口
func (spider *Spider) ChlikByLink() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		return spider.ChlikLink(ctx)
	})
}

//CommitBybutton 提交按钮
func (spider *Spider) CommitBybutton(ctx context.Context) error {
	var nodes []*cdp.Node
	err := chromedp.Nodes("//input[@type='submit']", &nodes, chromedp.BySearch).Do(ctx)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		log.Printf("no find //input[@type='submit'] node")
		return nil
	}
	for _, node := range nodes {
		//自动填写表单
		spider.fillForm(ctx)
		if !(node.AttributeValue("type") == "hidden" || node.AttributeValue("display") == "none") {
			//鼠标移动到button上
			err := chromedp.MouseClickNode(node, chromedp.ButtonType(input.Left)).Do(ctx)
			if err != nil {
				//log.Println("CommitBybutton MouseClickNode error:", err)
			}
			chromedp.Sleep(1 * time.Second)
		}
	}

	return nil
}

//fillForm 填写表单
func (spider *Spider) fillForm(ctx context.Context) error {
	var nodes []*cdp.Node
	//var res string
	//获取 input节点
	err := chromedp.Nodes("//input", &nodes).Do(ctx)
	if err != nil {
		fmt.Println("fillForm error: ", err)
	}
	if len(nodes) == 0 {
		return errors.New("no find node")
	}
	//移除input的 style 属性
	err = chromedp.Evaluate(removeAttribute, nil).Do(ctx)
	if err != nil {
		log.Fatal("removeAttribute error: ", err)
	}

	for _, node := range nodes {
		var ok bool
		chromedp.EvaluateAsDevTools(fmt.Sprintf(inViewportJS, node.FullXPath()), &ok).Do(ctx)
		if err != nil {
			log.Fatal("got  error:", err)
		}
		if !(node.AttributeValue("type") == "hidden" || node.AttributeValue("display") == "none") {
			//fmt.Println(node.Attributes)
			//填写用户名
			for _, name := range []string{"user", "用户名", "username"} {
				if v := node.AttributeValue("name"); name == v {
					//移动鼠标到目标节点上,模拟人类操作，也许会触发标签事件
					err = chromedp.MouseClickNode(node, chromedp.ButtonType(input.Left)).Do(ctx)
					if err != nil {
						log.Fatal("MouseClickNode error:", err)
					}
					err = chromedp.SendKeys(fmt.Sprintf(`input[name=%s]`, v), "admin").Do(ctx)
					if err != nil {
						log.Fatal("SendKeys user name error:", err)
					}
				}
			}
			//填写密码
			for _, name := range []string{"pwd", "密码", "pass", "password"} {
				if v := node.AttributeValue("name"); name == v {
					//移动鼠标到目标节点上,模拟人类操作，也许会触发标签事件
					err = chromedp.MouseClickNode(node, chromedp.ButtonType(input.Left)).Do(ctx)
					if err != nil {
						log.Fatal("MouseClickNode error:", err)
					}
					//println(node.FullXPath())
					err = chromedp.SendKeys(fmt.Sprintf(`input[name=%s]`, v), "password").Do(ctx)
					if err != nil {
						log.Fatal("SendKeys user name error:", err)
					}
				} else {
					//移动鼠标到目标节点上,模拟人类操作，也许会触发标签事件
					err = chromedp.MouseClickNode(node, chromedp.ButtonType(input.Left)).Do(ctx)
					if err != nil {
						log.Fatal("MouseClickNode error:", err)
					}
					//println(node.FullXPath())
					err = chromedp.SendKeys(fmt.Sprintf(`input[name=%s]`, v), "1").Do(ctx)
					if err != nil {
						log.Fatal("SendKeys user name error:", err)
					}
				}
			}

		}

	}
	return err
}

//ChlikLink 点击a标签
func (spider *Spider) ChlikLink(ctx context.Context) error {
	var nodes []*cdp.Node
	var res *runtime.RemoteObject
	var timestamp interface{}
	var u string
	var Linklist []cdp.NodeID

	if err := chromedp.EvaluateAsDevTools(sethreftarget, &res).
		Do(ctx); err != nil {
		log.Println("Evaluate: ", err)
		return err
	}

	chromedp.Location(&u).Do(ctx)

	err := chromedp.Nodes("a", &nodes, chromedp.ByQueryAll).Do(ctx)
	if err != nil {
		log.Println(": ", err)
		return err
	}

	if err := chromedp.Poll("atags", &timestamp, chromedp.WithPollingInterval(2*time.Second)).Do(ctx); err != nil {
		log.Println("Poll error: ", err)
		return err
	}

	if err := chromedp.WaitReady("a", chromedp.ByQueryAll).Do(ctx); err != nil {
		log.Println("WaitReady error: ", err)
		return err
	}
	for _, value := range nodes {
		// log.Println("node id :", value.NodeID)
		Linklist = append(Linklist, value.NodeID)
	}

	for _, link := range Linklist {
		if err := chromedp.EvaluateAsDevTools(sethreftarget, &res).
			Do(ctx); err != nil {
			log.Println("Evaluate: ", err)
			return err
		}
		if err := chromedp.Poll("atags", &timestamp, chromedp.WithPollingInterval(2*time.Second)).Do(ctx); err != nil {
			log.Println("Poll error: ", err)
			return err
		}
		if err := chromedp.WaitReady("a", chromedp.ByQueryAll).Do(ctx); err != nil {
			log.Println("WaitReady error: ", err)
			return err
		}

		err := chromedp.Nodes("a", &nodes, chromedp.ByQueryAll).Do(ctx)
		if err != nil {
			log.Println("ChlikLink error: ", err)
			return err
		}

		for _, n := range nodes {
			if n.NodeID == link {
				if !(n.AttributeValue("type") == "hidden" ||
					n.AttributeValue("display") == "none" ||
					n.AttributeValue("href") == "#") {
					_, err := chromedp.RunResponse(ctx, chromedp.MouseClickNode(n, chromedp.ButtonLeft))
					if err != nil {
						// //出现(-32000)error 代表dom节点已经更新，原来chromedp.Nodes获取的节点id失效
						log.Println("ChlikLink RunResponse error: ", err.Error(), "node Attribute:", n.Attributes)
					}
					break
				}
				break
			}
		}

	}

	return err
}
