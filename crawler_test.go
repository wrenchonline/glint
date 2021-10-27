package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	cf "wenscan/config"
	craw "wenscan/crawler"
	model2 "wenscan/model"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	color "github.com/logrusorgru/aurora"
)

func Test_Crawler(t *testing.T) {
	Spider := craw.Spider{}

	Spider.Init()
	cf := cf.Conf{}
	Conf := cf.GetConf()

	navigateReq := model2.Request{}
	u, _ := url.Parse(Conf.Url)

	navigateReq.URL = &model2.URL{*u}
	tab, err := craw.NewTabaObject(&Spider, navigateReq)
	if err != nil {
		t.Error(err)
	}

	err = tab.Crawler(nil)
	if err != nil {
		t.Error(err)
	}

	for _, value := range tab.ResultList {
		fmt.Println(color.Cyan(value.URL.String()))
	}

}

func Test_Navigate(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("request:", r.URL)
		if r.URL.Path == "/index" {
			fmt.Fprintf(w, `
<html>
<body>
<script>
    setTimeout(() => {
        window.open('/window.open');
    }, 10);
    setTimeout(() => {
        window.location.href = '/window.location';
    }, 20);
</script>
</body>
</html>`)
		} else if r.URL.Path == "/window.open" {
			fmt.Fprintf(w, `
				<html>
				<body>
				<h>hello world</h>
				</body>
				</html>`)
		}
	}))
	defer s.Close()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		// There are two kinds of navigations:
		// 1) navigate in the same page;
		// 2) navigate to a new tab.
		// Case one can be blocked by the "fetch.FailRequest".
		// Case two can be blocked with browser command line arguments: block-new-web-contents
		chromedp.Flag("block-new-web-contents", true),
		//chromedp.Flag("disable-popup-blocking", true),
		// If headless mode is disabled, case two will send the request to the server,
		// but the page is still blocked.
		chromedp.Flag("headless", false),
	)
	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx) //chromedp.WithDebugf(log.Printf),

	defer cancel()

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *fetch.EventRequestPaused:
			go func(ctx context.Context, ev *fetch.EventRequestPaused) {
				var a chromedp.Action
				// You need to decide which requests not to block.
				if strings.HasSuffix(ev.Request.URL, "/index") {
					a = fetch.ContinueRequest(ev.RequestID)
				} else {
					log.Println("EventRequestPaused:", ev.Request.URL)
					a = fetch.FailRequest(ev.RequestID, network.ErrorReasonAborted)
				}
				if err := chromedp.Run(ctx, a); err != nil {
					log.Println(err)
				}
			}(ctx, ev)
		case *page.EventWindowOpen:
			log.Println("EventWindowOpen:", ev.URL)
		}
	})

	if err := chromedp.Run(ctx,
		fetch.Enable(),
		chromedp.Navigate(s.URL+"/index"),
		chromedp.Sleep(2*time.Second),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var docNodeIDs []cdp.NodeID
			err := chromedp.NodeIDs(`script`, &docNodeIDs, chromedp.ByQuery).Do(ctx)
			if err != nil {
				return err
			}
			if len(docNodeIDs) != 0 {
				fmt.Println("find it!")
			}
			return nil
		}),
	); err != nil {
		log.Println(err)
	}

	time.Sleep(2 * time.Second)

}
