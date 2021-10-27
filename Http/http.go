package Http

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"
	log "wenscan/Log"
	ast "wenscan/ast"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	. "github.com/logrusorgru/aurora"
)

//Spider 爬虫资源，设计目的是爬网页，注意使用此结构的函数在多线程中没上锁是不安全的，理想状态为一条线程使用这个结构
type Spider struct {
	Ctx            *context.Context //存储着浏览器的资源
	Cancel         *context.CancelFunc
	Responses      chan []map[string]string
	ReqMode        string
	PostData       []byte
	Standardlen    int //爬虫请求的长度
	ReqUrlresplen  int
	Url            *url.URL
	Headers        map[string]string //请求头
	Isreponse      bool
	Currentcontent string
}

func (spider *Spider) Close() {
	defer (*spider.Cancel)()
	defer chromedp.Cancel(*spider.Ctx)
}

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

func (spider *Spider) Init() error {
	//gotException := make(chan bool, 1)
	spider.Responses = make(chan []map[string]string)
	options := []chromedp.ExecAllocatorOption{
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-xss-auditor", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("allow-running-insecure-content", true),
		chromedp.Flag("disable-webgl", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("block-new-web-contents", true),
		chromedp.Flag("blink-settings", "imagesEnabled=false"),
		chromedp.Flag("proxy-server", "http://127.0.0.1:8080"),
		chromedp.UserAgent(`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36`),
	}
	options = append(chromedp.DefaultExecAllocatorOptions[:], options...)
	c, cancel := chromedp.NewExecAllocator(context.Background(), options...)
	ctx, cancel := chromedp.NewContext(c)
	//timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	//监听Console.log事件
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		Response := make(map[string]string)
		Responses := []map[string]string{}
		switch ev := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			// fmt.Printf("* console.%s call:\n", ev.Type)
			for _, arg := range ev.Args {
				fmt.Printf("%s - %s\n", arg.Type, string(arg.Value))
				Response[string(ev.Type)] = strings.ReplaceAll(string(arg.Value), "\"", "")
				Responses = append(Responses, Response)
			}
			go func() {
				spider.Responses <- Responses
			}()
		case *runtime.EventExceptionThrown:
		case *fetch.EventRequestPaused:
			go func() {
				c := chromedp.FromContext(ctx)
				ctx := cdp.WithExecutor(ctx, c.Target)
				var req *fetch.ContinueRequestParams
				if spider.ReqMode == "POST" {
					req = fetch.ContinueRequest(ev.RequestID)
					req.URL = spider.Url.String()
					req.Headers = []*fetch.HeaderEntry{}
					//设置文件头
					for key, value := range spider.Headers {
						req.Headers = append(req.Headers, &fetch.HeaderEntry{Name: key, Value: value})
					}
					req.Method = "POST"
					req.PostData = base64.StdEncoding.EncodeToString(spider.PostData)
				} else {
					req = fetch.ContinueRequest(ev.RequestID)
				}
				if err := req.Do(ctx); err != nil {
					log.Printf("fetch.EventRequestPaused Failed to continue request: %v", err)
				}
			}()
		case *network.EventRequestWillBeSent:
		case *network.EventResponseReceived:
		case *page.EventJavascriptDialogOpening:
			fmt.Printf("* EventJavascriptDialogOpening.%s call:\n", ev.Type)
			fmt.Println(Red(ev.Message))
			Response[string(ev.Type)] = strings.ReplaceAll(ev.Message, "\"", "")
			Responses = append(Responses, Response)
			go func() {
				c := chromedp.FromContext(ctx)
				ctx := cdp.WithExecutor(ctx, c.Target)
				//关闭弹窗
				page.HandleJavaScriptDialog(false).Do(ctx)
				spider.Responses <- Responses
			}()
		}
	})
	spider.Cancel = &cancel
	spider.Ctx = &ctx
	err := chromedp.Run(
		*spider.Ctx,
		fetch.Enable(),
	)
	return err
}

//Sendreq 发送请求 url为空使用爬虫装载的url
func (spider *Spider) Sendreq() (string, error) {

	var res string
	// var mutex sync.Mutex
	// mutex.Lock()

	err := chromedp.Run(
		*spider.Ctx,
		chromedp.Navigate(spider.Url.String()),
		// // 等待直到html加载完毕
		chromedp.WaitReady(`html`, chromedp.ByQueryAll),
		//获取获取服务列表HTML
		chromedp.OuterHTML("html", &res, chromedp.ByQueryAll),
	)
	if err != nil {
		log.Error("error:", err)
	}
	return res, err
}

func (spider *Spider) GetRequrlparam() (url.Values, error) {
	if len(spider.Url.String()) == 0 {
		panic("request url is emtry")
	}
	u, err := url.Parse(spider.Url.String())
	if err != nil {
		panic(err)
	}
	m, err := url.ParseQuery(u.RawQuery)
	return m, err
}

//GetReqLensByHtml 二度获取请求的长度
func (spider *Spider) GetReqLensByHtml(JsonUrls *ast.JsonUrl) error {
	if len(spider.Url.String()) == 0 {
		panic("request url is emtry")
	}

	if JsonUrls.MetHod == "GET" {
		spider.ReqMode = "GET"
		spider.Url, _ = url.Parse(JsonUrls.Url)
		response, err := spider.Sendreq()
		if err != nil {
			return err
		}
		spider.Standardlen = len(response)
	} else {
		spider.ReqMode = "POST"
		spider.Url, _ = url.Parse(JsonUrls.Url)
		spider.PostData = []byte(JsonUrls.Data)
		response, err := spider.Sendreq()
		if err != nil {
			return err
		}
		spider.Standardlen = len(response)
	}

	return nil
}

//BuildPayload words和 extension 是映射关系
type BuildPayload struct {
	i     int
	value string
	words []string
}

func (g *BuildPayload) Next() bool {
	if g.i == len(g.words) {
		return false
	}
	g.value = g.words[g.i]
	g.i++
	return true
}

func (g *BuildPayload) Value() interface{} {
	return g.value
}

//GetPayloadValue 迭代 payload
func (g *BuildPayload) GetPayloadValue() (string, error) {
	if g.Next() {
		switch v := g.Value().(type) {
		case string:
			return v, nil
		}
	}
	return "", fmt.Errorf("the datas is nothing")
}

//PayloadHandle payload处理,把payload根据请求方式的不同修改 paramname
func (spider *Spider) PayloadHandle(payload string, reqmod string, paramname string) error {
	if reqmod == "GET" {
		params, err := spider.GetRequrlparam()
		if err != nil {
			return err
		}
		if len(params) == 0 {
			return fmt.Errorf("GET参数为空")
		}

		params[paramname][0] = payload
		spider.Url.RawQuery = params.Encode()
	} else {
		if len(spider.PostData) == 0 {
			return fmt.Errorf("POST参数为空")
		}

		spider.PostData = []byte(payload)
	}
	return nil
}

func (spider *Spider) CheckPayloadNormal(newpayload string, f func(html string) bool) bool {
	if spider.ReqMode == "GET" {
		params, err := spider.GetRequrlparam()
		if err != nil {
			panic(err.Error())
		}
		for param, _ := range params {
			spider.PayloadHandle(newpayload, "GET", param)
			html, err := spider.Sendreq()
			if err != nil {
				return false
			}
			if f(html) {
				return true
			}
		}
		return false
	} else {
		PostData := spider.PostData
		params := strings.Split(string(PostData), "&")
		for i, _ := range params {
			paramname := strings.Split(params[i], "=")[0]
			newpayload := paramname + "=" + newpayload
			newpayload1 := strings.ReplaceAll(string(PostData), params[i], newpayload)
			spider.PostData = PostData
			spider.PayloadHandle(newpayload1, "POST", "")
			html, err := spider.Sendreq()
			if err != nil {
				log.Error(err.Error())
			}
			if f(html) {
				return true
			}
			// spider.ReqMode = "Get"
			// spider.Url, _ = url.Parse("http://35.227.24.107/54313949cf/index.php")
			// gethtml, err := spider.Sendreq()
			// if f(gethtml) {
			// 	return true
			// }
		}
		return false
	}
}
