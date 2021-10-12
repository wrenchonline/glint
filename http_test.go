package main

import (
	"net/url"
	"testing"
	http "wenscan/http"
)

func TestCheckPayloadNormal(t *testing.T) {
	var err error
	Spider := http.Spider{}
	Spider.Init()
	defer Spider.Close()
	Spider.ReqMode = "POST"
	Spider.PostData = []byte("txtName=ecrrgaowle&mtxMessage=Crawl&user_token=873c33f5ece8c8308071890f478ded0b")
	Spider.Url, err = url.Parse("http://127.0.0.1/vulnerabilities/xss_s")
	if err != nil {
		t.Errorf(err.Error())
	}
	playload := "1232"
	Spider.CheckPayloadNormal(playload, func(html string) bool {
		return false
	})

}
