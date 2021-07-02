package httpex

import (
	"context"
	"time"
	log "wenscan/Log"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

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

func Sendreq(mode string, playload string) *string {
	//var ua string
	var res string
	// dir, err := ioutil.TempDir("", "chromedp-example")
	// if err != nil {
	// 	panic(err)
	// }
	ctx := context.Background()

	options := []chromedp.ExecAllocatorOption{
		//chromedp.DefaultExecAllocatorOptions[:],
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

	c, cc := chromedp.NewExecAllocator(ctx, options...)
	defer cc()
	// create context
	ctx, cancel := chromedp.NewContext(c)
	defer cancel()

	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	//listenForNetworkEvent(ctx)

	err := chromedp.Run(

		timeoutCtx,

		chromedp.Navigate(`http://192.168.166.95/xss.jsp?id=`+playload),
		// 等待直到html加载完毕
		chromedp.WaitReady(`html`, chromedp.BySearch),
		// 获取获取服务列表HTML
		chromedp.OuterHTML("html", &res, chromedp.ByQuery),
	)
	if err != nil {
		log.Error("error:", err)
	}
	log.Info("html:", res)
	return &res
}
