package reverse

import (
	"bytes"
	"fmt"
	"glint/proto"

	// "github.com/jweny/pocassist/pkg/conf"
	"glint/util"
	"net/url"
	"time"

	// "github.com/jweny/pocassist/pkg/conf"
	"github.com/valyala/fasthttp"
)

type Reverse1 struct {
	Url                string
	Flag               string
	Domain             string
	Ip                 string
	IsDomainNameServer bool
}

// use ceye api
func NewReverse() *proto.Reverse {
	ceyeDomain := "fkuior.ceye.io" //修改过的，建议重新写
	flag := util.RandLowLetterNumber(8)
	if ceyeDomain == "" {
		return &proto.Reverse{}
	}
	urlStr := fmt.Sprintf("http://%s.%s", flag, ceyeDomain)
	u, _ := url.Parse(urlStr)
	return &proto.Reverse{
		Flag:               flag,
		Url:                util.ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}

// use ceye api
func NewReverse1() interface{} {
	ceyeDomain := "fkuior.ceye.io" //修改过的，建议重新写
	flag := util.RandLowLetterNumber(8)
	if ceyeDomain == "" {
		return &proto.Reverse{}
	}
	urlStr := fmt.Sprintf("http://%s.%s", flag, ceyeDomain)
	u, _ := url.Parse(urlStr)
	return &Reverse1{
		Flag:               flag,
		Url:                u.String(),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}

func ReverseCheck(v interface{}, timeout int64) bool {
	if r, ok := v.(*proto.Reverse); ok {
		ceyeApiToken := "0e43a818cb3cd0d1326ae6fb147b96b0" //修改过的，建议重新写
		if ceyeApiToken == "" || r.Domain == "" {
			return false
		}
		// 延迟 x 秒获取结果
		time.Sleep(time.Second * time.Duration(timeout))
		// http://api.ceye.io/v1/records?token=0e43a818cb3cd0d1326ae6fb147b96b0&type=dns&filter=123456
		//check dns
		verifyUrl := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", ceyeApiToken, r.Flag)
		if GetReverseResp(verifyUrl) {
			return true
		} else {
			//	check request
			verifyUrl := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=http&filter=%s", ceyeApiToken, r.Flag)
			if GetReverseResp(verifyUrl) {
				return true
			}
		}
		return false
	} else if r, ok := v.(*Reverse1); ok {
		ceyeApiToken := "0e43a818cb3cd0d1326ae6fb147b96b0" //修改过的，建议重新写
		if ceyeApiToken == "" || r.Domain == "" {
			return false
		}
		// 延迟 x 秒获取结果
		time.Sleep(time.Second * time.Duration(timeout))
		// http://api.ceye.io/v1/records?token=0e43a818cb3cd0d1326ae6fb147b96b0&type=dns&filter=123456
		// check dns
		verifyUrl := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", ceyeApiToken, r.Flag)
		if GetReverseResp(verifyUrl) {
			return true
		} else {
			//	check request
			verifyUrl := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=http&filter=%s", ceyeApiToken, r.Flag)
			if GetReverseResp(verifyUrl) {
				return true
			}
		}
		return false
	}
	// r := *proto.Reverse
	return false
}

func GetReverseResp(verifyUrl string) bool {
	notExist := []byte(`"data": []`)
	fastReq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(fastReq)
	fastReq.SetRequestURI(verifyUrl)
	fastReq.Header.SetMethod(fasthttp.MethodGet)
	resp, err := util.DoFasthttpRequest(fastReq, false)
	if err != nil {
		return false
	}
	if !bytes.Contains(resp.Body, notExist) { // api返回结果不为空
		return true
	}
	return false
}
