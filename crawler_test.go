package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/url"
	"testing"
	"wenscan/ast"
	cf "wenscan/config"
	craw "wenscan/crawler"
	model2 "wenscan/model"

	"github.com/thoas/go-funk"
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

	tab, err := craw.NewTabObject(&Spider, navigateReq)

	if err != nil {
		t.Error(err)
	}

	err = tab.Crawler(nil)
	if err != nil {
		t.Error(err)
	}
	// results := []ast.Groups{}

	List := make(map[string][]ast.JsonUrl)
	funk.Map(tab.ResultList, func(r *model2.Request) bool {
		element := ast.JsonUrl{
			Url:     r.URL.String(),
			MetHod:  r.Method,
			Headers: r.Headers,
			Data:    r.PostData,
			Source:  r.Source}
		List[r.GroupsId] = append(List[r.GroupsId], element)
		return false
	})
	data, err := json.Marshal(List)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("./result.json", data, 666)
	if err != nil {
		log.Fatal(err)
	}

}

func Test_filter(t *testing.T) {
	const url = `https://ka-f.fontawesome.com/releases/v5.15.4/webfonts/free-fa-solid-900.woff2`
	if craw.FilterKey(url, craw.ForbidenKey) {
	} else {
		t.Errorf("test FilterKey() fail")
	}
}
