package main

import (
	"fmt"
	"net/url"
	"testing"
	"wenscan/ast"
	http "wenscan/http"
	log "wenscan/log"

	"github.com/logrusorgru/aurora"
)

func TestCheckPayloadNormal(t *testing.T) {
	var err error
	Spider := http.Spider{}
	log.DebugEnable(true)
	Spider.Init()
	defer Spider.Close()
	Spider.ReqMode = "GET"
	// Spider.PostData = []byte("txtName=ecrrgaowle&mtxMessage=Crawl&user_token=873c33f5ece8c8308071890f478ded0b")
	Spider.Url, err = url.Parse("http://35.227.24.107/68fba0189f/index.php")
	if err != nil {
		t.Errorf(err.Error())
	}
	playload := "67pSvN6I"
	htmls, _ := Spider.CheckPayloadNormal(playload)
	for _, v := range htmls {
		ast.SearchInputInResponse(playload, v)
		// fmt.Println(aurora.Red(OCC))
	}

	htmls, _ = Spider.CheckPayloadNormal(playload)
	for _, v := range htmls {
		OCC := ast.SearchInputInResponse(playload, v)
		fmt.Println(aurora.Red(OCC))
	}
}
