package main

import (
	"fmt"
	"net/url"
	"testing"
	cf "wenscan/config"
	craw "wenscan/crawler"
	model2 "wenscan/model"

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
	navigateReq.Headers = Conf.Headers
	tab, err := craw.NewTabaObject(&Spider, navigateReq)
	if err != nil {
		t.Error(err)
	}

	err = tab.Crawler(nil)
	if err != nil {
		t.Error(err)
	}

	for _, value := range tab.ResultList {
		fmt.Println(color.Sprintf("Url:%s Method:%s ", color.Cyan(value.URL.String()), color.Cyan(value.Method)))
		if value.PostData != "" {
			fmt.Println(color.Sprintf("POST:%s", color.Cyan(value.PostData)))
		}
	}

}
