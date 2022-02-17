package main

import (
	"context"
	"fmt"
	"glint/ast"
	"glint/config"
	"glint/crawler"
	craw "glint/crawler"
	"glint/logger"
	"glint/model"
	"glint/util"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/thoas/go-funk"
)

func Test_Crawler(t *testing.T) {
	logger.DebugEnable(true)
	TaskConfig := config.TaskConfig{}
	TaskConfig.Proxy = "127.0.0.1:7777"
	TaskConfig.NoHeadless = false
	TaskConfig.TabRunTimeout = 20 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := config.ReadTaskConf("./config.yaml", &TaskConfig)
	if err != nil {
		t.Errorf("test ReadTaskConf() fail")
	}
	murl, _ := url.Parse("http://192.168.166.8/vulnerabilities/xss_s")
	// murl2, _ := url.Parse("http://192.168.166.8")
	Headers := make(map[string]interface{})
	// Headers["HOST"] = "192.168.166.8"

	// Headers2 := make(map[string]interface{})
	// Headers2["HOST"] = "http://www.rongji.com/"

	targets := []*model.Request{
		&model.Request{
			URL:           &model.URL{URL: *murl},
			Method:        "GET",
			FasthttpProxy: TaskConfig.Proxy,
			Headers:       Headers,
		},
		// &model.Request{
		// 	URL:           &model.URL{URL: *murl2},
		// 	Method:        "GET",
		// 	FasthttpProxy: TaskConfig.Proxy,
		// 	Headers:       Headers2,
		// },
	}
	task, err := crawler.NewCrawlerTask(&ctx, targets, TaskConfig)
	if err != nil {
		t.Errorf("create crawler task failed.")
		os.Exit(-1)
	}
	if len(targets) != 0 {
		// logger.Info("sdads")
		msg := fmt.Sprintf("Init crawler task, host: %s, max tab count: %d, max crawl count: %d.",
			targets[0].URL.Host, TaskConfig.MaxTabsCount, TaskConfig.MaxCrawlCount)
		logger.Info(msg)

		logger.Info("filter mode: %s", TaskConfig.FilterMode)
	}
	logger.Info("Start crawling.")
	task.Run()
	result := task.Result
	for _, rest := range result.AllReqList {
		fmt.Println(aurora.Red(rest))
	}
	ReqList := make(map[string][]ast.JsonUrl)
	funk.Map(result.ReqList, func(r *model.Request) bool {
		// element := make(map[string]interface{})
		element := ast.JsonUrl{
			Url:     r.URL.String(),
			MetHod:  r.Method,
			Headers: r.Headers,
			Data:    r.PostData,
			Source:  r.Source}
		ReqList[r.GroupsId] = append(ReqList[r.GroupsId], element)
		return false
	})
	util.SaveCrawOutPut(ReqList, "result2.json")
}

func Test_filter(t *testing.T) {
	const url = `https://ka-f.fontawesome.com/releases/v5.15.4/webfonts/free-fa-solid-900.woff2`
	if craw.FilterKey(url, craw.ForbidenKey) {
	} else {
		t.Errorf("test FilterKey() fail")
	}
}
