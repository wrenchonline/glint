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

	"github.com/thoas/go-funk"
)

func Test_Crawler(t *testing.T) {
	logger.DebugEnable(true)
	TaskConfig := config.TaskConfig{}
	TaskConfig.Proxy = ""
	TaskConfig.NoHeadless = true
	TaskConfig.TabRunTimeout = 20 * time.Second
	var Results []*crawler.Result
	ctx, _ := context.WithCancel(context.Background())
	// actx, acancel := context.WithTimeout(ctx, TaskConfig.TabRunTimeout)
	// defer acancel()
	err := config.ReadTaskConf("config.yaml", &TaskConfig)
	if err != nil {
		t.Errorf("test ReadTaskConf() fail")
	}
	murl, _ := url.Parse("http://www.dachenglaw.com/")
	Headers := make(map[string]interface{})
	targets := &model.Request{
		URL:           &model.URL{URL: *murl},
		Method:        "GET",
		FasthttpProxy: TaskConfig.Proxy,
		Headers:       Headers,
	}
	task, err := crawler.NewCrawlerTask(&ctx, targets, TaskConfig)
	if err != nil {
		t.Errorf("create crawler task failed.")
		os.Exit(-1)
	}
	msg := fmt.Sprintf("Init crawler task, host: %s, max tab count: %d, max crawl count: %d.",
		targets.URL.Host, TaskConfig.MaxTabsCount, TaskConfig.MaxCrawlCount)
	logger.Info(msg)
	logger.Info("filter mode: %s", TaskConfig.FilterMode)
	logger.Info("Start crawling.")
	go task.Run()
	task.Waitforsingle()
	result := task.Result
	// for _, rest := range result.AllReqList {
	// 	fmt.Println(aurora.Red(rest))
	// }
	ReqList := make(map[string][]ast.JsonUrl)

	ALLURLS := make(map[string][]interface{})
	URLSList := make(map[string]interface{})

	//ALLURLS := make(map[string][]interface{})
	ALLURI := make(map[string][]interface{})
	// URLSList := make(map[string]interface{})
	// URISList := make(map[string]interface{})

	mresult := task.Result
	mresult.Hostid = task.Result.Hostid
	mresult.HOSTNAME = task.HostName
	fmt.Printf("爬取 %s 域名结束", task.HostName)
	Results = append(Results, mresult)

	CrawlerConvertToMap(Results, &ALLURI, nil, true)

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
	util.SaveCrawOutPut(ReqList, "./json_testfile/apperror.json")
	CrawlerConvertToMap(Results, &ALLURLS, nil, false)
	for s, v := range ReqList {
		URLSList[s] = v
	}
	fmt.Println("PASS")
}

func Test_filter(t *testing.T) {
	const url = `https://ka-f.fontawesome.com/releases/v5.15.4/webfonts/free-fa-solid-900.woff2`
	if craw.FilterKey(url, craw.ForbidenKey) {
	} else {
		t.Errorf("test FilterKey() fail")
	}
}
