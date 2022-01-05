package main

import (
	"glint/logger"
	"glint/util"
	"testing"
)

func Test_Post(t *testing.T) {
	body := "file=123456.fkuior.ceye.io&read=load+file"
	param, _ := util.ParseUri("", []byte(body), "POST")
	logger.Debug("%v", param)
	pal := param.SetPayload("", "122", "POST")
	logger.Debug("%v", pal)
	//Get
	param1, _ := util.ParseUri("https://www.google.com/search?q=dasdas&oq=dasdas", []byte(""), "GET")
	logger.Debug("%v", param1)
	pal1 := param1.SetPayload("https://www.google.com/search?q=dasdas&oq=dasdas", "122", "GET")
	logger.Debug("%v", pal1)
}
