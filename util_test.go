package main

import (
	"fmt"
	"glint/logger"
	"glint/util"
	"regexp"
	"testing"
	"time"
	"unsafe"
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

	var tsrs = `192.168.166.16 192.168.166.7`
	regexIp := `\b(192\.168\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))|172\.(?:16|17|18|19|(?:2[0-9])|30|31)\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))|10\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5])))\b`
	RE, _ := regexp.Compile(regexIp)
	ips := RE.FindAllString(tsrs, -1)
	fmt.Println(ips)

	var tsrss = `"Db_user"="1221"
	"Db_pass"='20sdasdasd'`
	regexx := `(?i)(?m)(['"]?(db[\-_])?(uid|user|username)['"]?\s?(:|=)\s*['"]?([A-Za-z0-9_\-@$!%*#?&]){3,}['"]?[,]?([\r\n]+)\s*['"]?(db[\-_])?(pass|pwd|passwd|password)['"]?\s?(:|=)\s*['"]?([A-Za-z0-9_\-@$!%*#?&]){6,}['"]?([,\r\n]|$))`
	RE1, _ := regexp.Compile(regexx)
	m := RE1.FindAllString(tsrss, -1)
	fmt.Println(m)

	tsrsss := "/cn/about\r\n\r\r\n   "
	r := regexp.MustCompile(`(\r|\n|\s+)`)
	_url := r.ReplaceAllString(tsrsss, "")
	fmt.Println(_url)

}

func Test_Rate(t *testing.T) {
	//测试每秒发送10个链接,测试10秒
	myRate := util.Rate{}
	// bShutdown := make(chan bool)
	myRate.InitRate(20)
	for i := 0; i < 100; i++ {
		go func(r *util.Rate, i int) {
			logger.Info("Start id:%d", i)
			r.LimitWait()
			if i == 99 {
				logger.Info("End id:%d Get Current Count: %d", i, r.GetIndex())
			}
		}(&myRate, i)
	}
	time.Sleep(time.Second * 20)
}

func Test_Ts(t *testing.T) {
	nm := util.NetworkManager{}
	arrays := unsafe.Sizeof(nm)
	// consumeGb := 1073741824
	// Count := consumeGb / arrays
	fmt.Println(arrays) // 8
}

func Test_AES_CBC_SHA256(t *testing.T) {
	orig := "hello world"
	key := "0123456789012345"
	fmt.Println("原文：", orig)
	encryptCode := util.AesEncrypt(orig, key)
	fmt.Println("密文：", encryptCode)
	decryptCode := util.AesDecrypt(encryptCode, key)
	fmt.Println("解密结果：", decryptCode)
}
