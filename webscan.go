package main

import (
	"wenscan/Helper"
	log "wenscan/Log"
	"wenscan/Xss"
	http "wenscan/http"

	"github.com/thoas/go-funk"
)

func main() {
	log.DebugEnable(false)
	playload := Xss.RandStringRunes(12)
	Spider := http.Spider{}
	Spider.Init()
	defer Spider.Close()
	html := Spider.Sendreq("", playload)
	log.Info(*html)
	locations := Helper.SearchInputInResponse(playload, *html)
	if len(locations) == 0 {
		log.Error("SearchInputInResponse error,U can convert html encode")
	}
	var result interface{}
	VulOK := false
	result = funk.Map(locations, func(item Helper.Occurence) bool {
		if item.Type == "html" {
			g := new(Xss.Generator)
			g.GeneratorPayload(Xss.Htmlmode, playload, item)
			for newpayload, methods := g.GetPayloadValue(); len(newpayload) != 0; {
				html := Spider.Sendreq("", newpayload)
				locations := Helper.SearchInputInResponse(playload, *html)
				if g.CheckXssVul(locations, methods, Spider) {
					log.Info("《html》html标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
					break
				}
			}
		} else if item.Type == "attibute" {
			//假设如果渲染得值在key中
			if item.Details.Content == "key" {
				g := new(Xss.Generator)
				g.GeneratorPayload(Xss.Attibute, playload, item)
				for newpayload, methods := g.GetPayloadValue(); len(newpayload) != 0; {
					html := Spider.Sendreq("", newpayload)
					locations := Helper.SearchInputInResponse(playload, *html)
					if g.CheckXssVul(locations, methods, Spider) {
						log.Info("《attibute》attibute标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
						break
					}
				}
			} else {
				//否则就在value中
				g := new(Xss.Generator)
				g.GeneratorPayload(Xss.Attibute, playload, item)
				for newpayload, methods := g.GetPayloadValue(); len(newpayload) != 0; {
					html := Spider.Sendreq("", newpayload)
					locations := Helper.SearchInputInResponse(playload, *html)
					if g.CheckXssVul(locations, methods, Spider) {
						log.Info("《attibute》attibute标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
						break
					}
				}
			}
		} else if item.Type == "script" {
			g := new(Xss.Generator)
			g.GeneratorPayload(Xss.Script, playload, item)
			for newpayload, methods := g.GetPayloadValue(); len(newpayload) != 0; {
				html := Spider.Sendreq("", newpayload)
				locations := Helper.SearchInputInResponse(playload, *html)
				if g.CheckXssVul(locations, methods, Spider) {
					log.Info("《attibute》attibute标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
					break
				}
			}
		}
		return VulOK
	})

	if funk.Contains(result, true) {
		//log.Info("html标签可被闭合")
	}

}
