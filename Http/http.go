package httpex

import (
	"context"
	"time"
	log "wenscan/Log"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

//Spider 爬虫资源，设计目的是爬网页，注意使用此结构的函数在多线程中没上锁是不安全的，理想状态为一条线程使用这个结构
type Spider struct {
	Ctx    *context.Context //存储着浏览器的资源
	Cancel *context.CancelFunc
}

func (spider *Spider) Close() {
	defer (*spider.Cancel)()
	defer chromedp.Cancel(*spider.Ctx)
}

func (spider *Spider) Init() {
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
	spider.Cancel = &cancel
	spider.Ctx = &timeoutCtx
}

func listenForNetworkEvent(ctx context.Context) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventResponseReceived:
			resp := ev.Response
			if len(resp.Headers) != 0 {
				log.Info("received headers: %s", resp.Headers)
			}
		}
	})
}

//Sendreq 发送请求
func (spider *Spider) Sendreq(mode string, playload string) *string {
	var res string

	err := chromedp.Run(

		*spider.Ctx,

		chromedp.Navigate(`http://192.168.166.95/xss2.jsp?id=`+playload),
		// 等待直到html加载完毕
		chromedp.WaitReady(`html`, chromedp.BySearch),
		// 获取获取服务列表HTML
		chromedp.OuterHTML("html", &res, chromedp.ByQuery),
	)
	if err != nil {
		log.Error("error:", err)
	}
	log.Debug("html:", res)
	return &res
}
