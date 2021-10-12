package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"testing"
	"wenscan/Helper"
	log "wenscan/Log"
	"wenscan/Xss"
	cf "wenscan/config"
	http "wenscan/http"

	"github.com/fatih/color"
	"github.com/thoas/go-funk"
)

func TestXSS(t *testing.T) {
	log.DebugEnable(false)
	playload := Xss.RandStringRunes(12)
	Spider := http.Spider{}
	Spider.Init()
	var locationDS []Helper.Occurence
	defer Spider.Close()
	c := cf.Conf{}
	//读取配置文件
	conf := c.GetConf()
	Spider.ReqMode = conf.ReqMode
	if err := Spider.SetCookie(conf); err != nil {
		panic(err)
	}

	jsonFile, err := os.Open("xss_s.json")

	// 最好要处理以下错误
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var JsonUrls []Helper.JsonUrl
	err = json.Unmarshal([]byte(byteValue), &JsonUrls)
	// 最好要处理以下错误
	if err != nil {
		fmt.Println(err)
	}

	for _, data := range JsonUrls {
		Spider.ReqMode = data.MetHod
		Spider.Url, err = url.Parse(data.Url)
		Spider.PostData = []byte(data.Data)
		color.Red(Spider.Url.String())
		if err != nil {
			color.Red(err.Error())
		}

		if Spider.CheckPayloadNormal(playload, func(html string) bool {
			locations := Helper.SearchInputInResponse(playload, html)
			if len(locations) != 0 {
				locationDS = locations
				return true
			}
			return false
		}) {
			var result interface{}
			VulOK := false
			result = funk.Map(locationDS, func(item Helper.Occurence) bool {
				if item.Type == "html" {
					g := new(Xss.Generator)
					g.GeneratorPayload(Xss.Htmlmode, playload, item)
					for {
						newpayload, methods := g.GetPayloadValue()
						if len(newpayload) != 0 {
							if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
								locations := Helper.SearchInputInResponse(playload, html)
								if g.CheckXssVul(locations, methods, Spider) {
									log.Info("Xss::html标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
									return true
								}
								return false
							}) {
								break
							}
						} else {
							break
						}
					}
				} else if item.Type == "attibute" {
					//假设如果渲染得值在key中
					if item.Details.Content == "key" {
						g := new(Xss.Generator)
						g.GeneratorPayload(Xss.Attibute, playload, item)
						for {
							newpayload, methods := g.GetPayloadValue()
							if len(newpayload) != 0 {
								if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
									locations := Helper.SearchInputInResponse(playload, html)
									if g.CheckXssVul(locations, methods, Spider) {
										log.Info("Xss::attibute标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
										return true
									}
									return false
								}) {
									break
								}
							} else {
								break
							}

						}
					} else {
						//否则就在value中
						g := new(Xss.Generator)
						g.GeneratorPayload(Xss.Attibute, playload, item)
						for {
							newpayload, methods := g.GetPayloadValue()
							if len(newpayload) != 0 {
								if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
									locations := Helper.SearchInputInResponse(playload, html)
									if g.CheckXssVul(locations, methods, Spider) {
										log.Info("Xss::attibute标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
										return true
									}
									return false
								}) {
									break
								}
							} else {
								break
							}
						}
					}
				} else if item.Type == "script" {
					g := new(Xss.Generator)
					g.GeneratorPayload(Xss.Script, playload, item)
					for {
						newpayload, methods := g.GetPayloadValue()
						if len(newpayload) != 0 {
							if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
								locations := Helper.SearchInputInResponse(playload, html)
								if g.CheckXssVul(locations, methods, Spider) {
									log.Info("Xss::script标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
									return true
								}
								return false
							}) {
								break
							}
						} else {
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
	}

}
