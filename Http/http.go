package Http

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"
	log "wenscan/Log"
	cf "wenscan/config"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/fatih/color"
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

func (spider *Spider) SetCookie(conf *cf.Conf) error {
	for _, i := range conf.Cookies {
		err := chromedp.Run(*spider.Ctx, SetCookie(i.Name, i.Value, i.Domain, i.Path, i.HttpOnly, i.Secure))
		if err != nil {
			log.Error("error:", err)
			return err
		}
	}
	return nil
}

func (spider *Spider) Init() error {
	//gotException := make(chan bool, 1)
	spider.Responses = make(chan []map[string]string)
	options := []chromedp.ExecAllocatorOption{
		chromedp.Flag("headless", false),
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
		chromedp.UserAgent(`Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36`),
	}
	options = append(options, chromedp.DefaultExecAllocatorOptions[:]...)
	c, cancel := chromedp.NewExecAllocator(context.Background(), options...)
	ctx, cancel := chromedp.NewContext(c)
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	//监听Console.log事件
	chromedp.ListenTarget(timeoutCtx, func(ev interface{}) {
		Response := make(map[string]string)
		Responses := []map[string]string{}
		switch ev := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			fmt.Printf("* console.%s call:\n", ev.Type)
			for _, arg := range ev.Args {
				fmt.Printf("%s - %s\n", arg.Type, string(arg.Value))
				Response[string(ev.Type)] = strings.ReplaceAll(string(arg.Value), "\"", "")
				Responses = append(Responses, Response)
			}
			go func() {
				spider.Responses <- Responses
			}()
		case *runtime.EventExceptionThrown:
			s := ev.ExceptionDetails.Error()
			fmt.Printf("* %s\n", s)
		case *fetch.EventRequestPaused:
			go func() {
				c := chromedp.FromContext(ctx)
				e := cdp.WithExecutor(ctx, c.Target)
				req := fetch.ContinueRequest(ev.RequestID)
				if spider.ReqMode == "POST" {
					//req.Headers = []*fetch.HeaderEntry{{"Myheader", "example"}}
					req.Method = "POST"
					req.PostData = base64.StdEncoding.EncodeToString(spider.PostData)
					color.Yellow("post req: ", req)
				}
				if err := req.Do(e); err != nil {
					log.Printf("fetch.EventRequestPaused Failed to continue request: %v", err)
				}
			}()
		}
	})
	spider.Cancel = &cancel
	spider.Ctx = &timeoutCtx
	err := chromedp.Run(
		*spider.Ctx,
		fetch.Enable(),
	)
	return err
}

//Sendreq 发送请求
func (spider *Spider) Sendreq(url string) *string {

	var res string
	// var mutex sync.Mutex
	// mutex.Lock()
	err := chromedp.Run(
		*spider.Ctx,
		chromedp.Navigate(url),
		// 等待直到html加载完毕
		chromedp.WaitReady(`html`, chromedp.BySearch),
		// 获取获取服务列表HTML
		chromedp.OuterHTML("html", &res, chromedp.ByQuery),
	)
	if err != nil {
		log.Error("error:", err)
	}
	// mutex.Unlock()
	// log.Debug("html:", res)

	return &res
}

func ShowCookies() chromedp.Action {
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

func SetCookie(name, value, domain, path string, httpOnly, secure bool) chromedp.Action {
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
