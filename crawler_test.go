package main

import (
	"fmt"
	"net/url"
	"os"
	"testing"
	"wenscan/config"
	"wenscan/crawler"
	craw "wenscan/crawler"
	log "wenscan/log"
	"wenscan/model"

	"github.com/logrusorgru/aurora"
)

func Test_Crawler(t *testing.T) {
	TaskConfig := config.TaskConfig{}
	err := config.ReadTaskConf("./config.yaml", &TaskConfig)
	if err != nil {
		t.Errorf("test ReadTaskConf() fail")
	}
	murl, _ := url.Parse("http://www.rongji.com")
	Headers := make(map[string]interface{})
	Headers["HOST"] = "www.rongji.com"
	targets := []*model.Request{
		&model.Request{
			URL:           &model.URL{URL: *murl},
			Method:        "GET",
			FasthttpProxy: TaskConfig.Proxy,
			Headers:       Headers,
		},
	}
	task, err := crawler.NewCrawlerTask(targets, TaskConfig)
	if err != nil {
		t.Errorf("create crawler task failed.")
		os.Exit(-1)
	}
	if len(targets) != 0 {
		log.Info(fmt.Sprintf("Init crawler task, host: %s, max tab count: %d, max crawl count: %d.",
			targets[0].URL.Host, TaskConfig.MaxTabsCount, TaskConfig.MaxCrawlCount))
		log.Info("filter mode: %s", TaskConfig.FilterMode)
	}
	log.Info("Start crawling.")
	task.Run()
	result := task.Result
	fmt.Println(aurora.Red(result.ReqList))
}

func Test_filter(t *testing.T) {
	const url = `https://ka-f.fontawesome.com/releases/v5.15.4/webfonts/free-fa-solid-900.woff2`
	if craw.FilterKey(url, craw.ForbidenKey) {
	} else {
		t.Errorf("test FilterKey() fail")
	}
}
