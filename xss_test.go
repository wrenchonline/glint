package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"testing"
	log "wenscan/Log"
	ast "wenscan/ast"
	cf "wenscan/config"
	http "wenscan/http"

	"github.com/k0kubun/go-ansi"
	. "github.com/logrusorgru/aurora"
	"github.com/mitchellh/colorstring"
	"github.com/thoas/go-funk"
)

func TestXSS(t *testing.T) {
	log.DebugEnable(false)
	// playload := Xss.RandStringRunes(12)
	Spider := http.Spider{}
	Spider.Init()
	// var locationDS []ast.Occurence
	defer Spider.Close()
	c := cf.Conf{}
	//读取配置文件
	conf := c.GetConf()
	Spider.ReqMode = conf.ReqMode
	// if err := Spider.SetCookie(conf); err != nil {
	// 	panic(err)
	// }

	jsonFile, err := os.Open("result.json")

	// 最好要处理以下错误
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var JsonUrls [][]ast.JsonUrl
	err = json.Unmarshal([]byte(byteValue), &JsonUrls)
	// 最好要处理以下错误
	if err != nil {
		fmt.Println(err)
	}

	// for _, data := range JsonUrls {
	// 	Spider.ReqMode = data.MetHod
	// 	Spider.Url, err = url.Parse(data.Url)
	// 	Spider.PostData = []byte(data.Data)
	// 	Spider.Headers = data.Headers
	// 	color.Red(Spider.Url.String())
	// 	if err != nil {
	// 		color.Red(err.Error())
	// 	}
	// 	if Spider.CheckPayloadNormal(playload, func(html string) bool {
	// 		locations := ast.SearchInputInResponse(playload, html)
	// 		if len(locations) != 0 {
	// 			locationDS = locations
	// 			return true
	// 		}
	// 		return false
	// 	}) {
	// 		var result interface{}
	// 		VulOK := false
	// 		result = funk.Map(locationDS, func(item ast.Occurence) bool {
	// 			if item.Type == "html" {
	// 				g := new(Xss.Generator)
	// 				g.GeneratorPayload(Xss.Htmlmode, playload, item)
	// 				for {
	// 					Spider.PostData = []byte(data.Data)
	// 					newpayload, methods := g.GetPayloadValue()
	// 					if len(newpayload) != 0 {
	// 						if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
	// 							locations := ast.SearchInputInResponse(playload, html)
	// 							if g.CheckXssVul(locations, methods, Spider) {
	// 								log.Info("Xss::html标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
	// 								return true
	// 							}
	// 							return false
	// 						}) {
	// 							break
	// 						}
	// 					} else {
	// 						break
	// 					}
	// 				}
	// 			} else if item.Type == "attibute" {
	// 				//假设如果渲染得值在key中
	// 				if item.Details.Content == "key" {
	// 					g := new(Xss.Generator)
	// 					g.GeneratorPayload(Xss.Attibute, playload, item)
	// 					for {
	// 						Spider.PostData = []byte(data.Data)
	// 						newpayload, methods := g.GetPayloadValue()
	// 						if len(newpayload) != 0 {
	// 							if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
	// 								locations := ast.SearchInputInResponse(playload, html)
	// 								if g.CheckXssVul(locations, methods, Spider) {
	// 									log.Info("Xss::attibute标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
	// 									return true
	// 								}
	// 								return false
	// 							}) {
	// 								break
	// 							}
	// 						} else {
	// 							break
	// 						}
	// 					}
	// 				} else {
	// 					//否则就在value中
	// 					g := new(Xss.Generator)
	// 					g.GeneratorPayload(Xss.Attibute, playload, item)
	// 					for {
	// 						Spider.PostData = []byte(data.Data)
	// 						newpayload, methods := g.GetPayloadValue()
	// 						if len(newpayload) != 0 {
	// 							if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
	// 								locations := ast.SearchInputInResponse(playload, html)
	// 								if g.CheckXssVul(locations, methods, Spider) {
	// 									log.Info("Xss::attibute标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
	// 									return true
	// 								}
	// 								return false
	// 							}) {
	// 								break
	// 							}
	// 						} else {
	// 							break
	// 						}
	// 					}
	// 				}
	// 			} else if item.Type == "script" {
	// 				g := new(Xss.Generator)
	// 				g.GeneratorPayload(Xss.Script, playload, item)
	// 				for {
	// 					Spider.PostData = []byte(data.Data)
	// 					newpayload, methods := g.GetPayloadValue()
	// 					if len(newpayload) != 0 {
	// 						if Spider.CheckPayloadNormal(newpayload, func(html string) bool {
	// 							locations := ast.SearchInputInResponse(playload, html)
	// 							if g.CheckXssVul(locations, methods, Spider) {
	// 								log.Info("Xss::script标签可被闭合 发现xss漏洞 payloads:%s", newpayload)
	// 								return true
	// 							}
	// 							return false
	// 						}) {
	// 							break
	// 						}
	// 					} else {
	// 						break
	// 					}
	// 				}
	// 			}
	// 			return VulOK
	// 		})

	// 		if funk.Contains(result, true) {
	// 			//log.Info("html标签可被闭合")
	// 		}
	// 	}
	// }

}

func Test_JS(t *testing.T) {

	io := ansi.NewAnsiStdout()
	log.DebugEnable(true)
	var sourceFound bool
	var sinkFound bool
	script := `
	
	`
	sources := `document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage`
	sinks := `eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location`
	newlines := strings.Split(script, "\n")

	matchsinks := funk.Map(newlines, func(x string) string {
		//parts := strings.Split(x, "var ")
		r, _ := regexp.Compile(sinks)
		C := r.FindAllStringSubmatch(x, -1)
		if len(C) != 0 {
			fmt.Println(Sprintf(Magenta("sinks match :%v \n"), Red(C[0][0])))
			return "vul"
		}
		return ""
	})

	matchsources := funk.Map(newlines, func(x string) string {
		r, _ := regexp.Compile(sources)
		C := r.FindAllStringSubmatch(x, -1)
		if len(C) != 0 {
			fmt.Println(Sprintf(Magenta("sources match :%v \n"), Yellow(C[0][0])))
			return "vul"
		}
		return ""
	})

	if value, ok := matchsources.([]string); ok {
		if funk.Contains(value, "vul") {
			sourceFound = true
		}
	}

	if value, ok := matchsinks.([]string); ok {
		if funk.Contains(value, "vul") {
			sinkFound = true
		}
	}

	if sourceFound && sinkFound {
		colorstring.Fprintf(io, "[red] 发现DOM XSS漏洞，该对应参考payload代码应由研究人员构造 \n")
	}

	// ast, err := js.Parse(parse.NewInputString(script))
	// if err != nil {
	// 	t.Error(err.Error())
	// }

	// for _, v := range ast.Declared {
	// 	fmt.Println(Sprintf(Magenta("ast.Declared:%s"), Blue(string(v.Data))))
	// }

	// for _, v := range ast.List {
	// 	v.
	// }
	// fmt.Println("JS:", ast.String())
}
