package main

import (
	"fmt"
	"glint/logger"
	"glint/util"
	"regexp"
	"testing"
)

func Test_Post(t *testing.T) {
	body := "file=123456.fkuior.ceye.io&read=load+file"
	param, _ := util.ParseUri("", []byte(body), "POST", "application/x-www-form-urlencoded")
	logger.Debug("%v", param)
	pal := param.SetPayload("", "122", "POST")
	logger.Debug("%v", pal)
	//Get
	param1, _ := util.ParseUri("https://www.google.com/search?q=dasdas&oq=dasdas", []byte(""), "GET", "None")
	logger.Debug("%v", param1)
	pal1 := param1.SetPayload("https://www.google.com/search?q=dasdas&oq=dasdas", "122", "GET")
	logger.Debug("%v", pal1)
}

func Test_For(t *testing.T) {
	for i := 0; i < 2; i++ {
		fmt.Printf("%d", i)
	}
}

func Test_Regex(t *testing.T) {
	var tsr = `我的邮箱 ljl260435988@gmail.com`
	var regexemails = `(?i)([_a-z\d\-\.]+@([_a-z\d\-]+(\.[a-z]+)+))`
	re, _ := regexp.Compile(regexemails)
	result := re.FindString(tsr)
	fmt.Println(result)
}
