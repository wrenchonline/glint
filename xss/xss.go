package xss

import (
	"bytes"
	"errors"
	"fmt"
	"glint/ast"
	"glint/brohttp"
	"glint/log"
	"glint/payload"
	"glint/plugin"
	"glint/util"
	"math/rand"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"

	"github.com/thoas/go-funk"
)

type stf struct {
	mode Checktype
	Tag  string
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

var (
	Htmlmode = 1
	Comment  = 2
	Attibute = 3
	Script   = 4
)

type Checktype string

const (
	CheckTag        Checktype = "Attibute" //检测标签
	CheckValue      Checktype = "Value"    //检测值
	CheckConsoleLog Checktype = "Console"  //检测控制台输出
	CheckDialog     Checktype = "Dialog"   //检测窗口弹出
)

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

//Generator words和 extension 是映射关系
type Generator struct {
	i          int
	value      string
	IsNeedFlag bool
	mode       Checktype
	Tag        string
	words      []string
	extension  []PayloadMode
	flag       string
}

func (g *Generator) Next() bool {
	if g.i == len(g.words) {
		return false
	}
	g.value = g.words[g.i]
	g.mode = g.extension[g.i].Mode
	g.Tag = g.extension[g.i].CheckTag
	g.IsNeedFlag = g.extension[g.i].IsNeedFlag
	g.i++
	return true
}

func (g *Generator) Value() interface{} {
	return g.value
}

type Kv struct {
	K bytes.Buffer
	V bytes.Buffer
}

type PayloadMode struct {
	Mode       Checktype
	IsNeedFlag bool
	payload    string
	CheckTag   string
}

//CheckHtmlNodeAttributesKey 检测是否存在对应的key值
func CheckHtmlNodeAttributes(s ast.Occurence, types string, name string, HasPrefix bool) (bool, Kv) {
	var Attributes Kv
	c := funk.Map(*s.Details.Attributes, func(A ast.Attribute) bool {
		if HasPrefix {
			if types == "key" {
				if strings.HasPrefix(A.Key, name) {
					Attributes.K.Reset()
					Attributes.V.Reset()
					Attributes.K.WriteString(A.Key)
					Attributes.V.WriteString(A.Key)
					return true
				}
			} else {
				if strings.HasPrefix(A.Val, name) {
					Attributes.K.Reset()
					Attributes.V.Reset()
					Attributes.K.WriteString(A.Key)
					Attributes.V.WriteString(A.Key)
					return true
				}
			}
		} else {
			if types == "key" {
				if A.Key == name {
					Attributes.K.Reset()
					Attributes.V.Reset()
					Attributes.K.WriteString(A.Key)
					Attributes.V.WriteString(A.Key)
					return true
				}
			} else {
				if A.Val == name {
					Attributes.K.Reset()
					Attributes.V.Reset()
					Attributes.K.WriteString(A.Key)
					Attributes.V.WriteString(A.Key)
					return true
				}
			}
		}
		return false
	})
	if funk.Contains(c, true) {
		return true, Attributes
	}
	return false, Attributes
}

func Test_CheckHtmlNodeAttributesKey() {
	detail := ast.Node{Tagname: "attibute", Content: "key", Attributes: &[]ast.Attribute{{Key: "srcdoc", Val: "dsadsadadsa"}}}
	test := ast.Occurence{Details: detail}
	if ok, _ := CheckHtmlNodeAttributes(test, "key", "srcdoc", false); ok {
		log.Debug("ok")
	}
}

//给payload做扩展属性
func (g *Generator) mapmode(Mode Checktype, CheckTag string, IsNeedFlag bool) {
	mode := funk.Map(g.words, func(payload string) PayloadMode {
		var mode PayloadMode
		mode.Mode = Mode
		mode.IsNeedFlag = IsNeedFlag
		mode.payload = payload
		mode.CheckTag = CheckTag
		return mode
	})
	if v, ok := mode.([]PayloadMode); ok {
		g.extension = append(g.extension, v...)
	}
}

type Callback func(msg string) string

func (g *Generator) CopyPayLoadtoXSS(payloaddata payload.PayloadData, Tagmode string, callback Callback) {
	xsspayloads := payloaddata.Xss[Tagmode].([]interface{})
	for _, v := range xsspayloads {
		s := v.(map[string]interface{})
		mytype := s["CheckType"].(string)
		PayLoad := s["PayLoad"].(string)
		if callback != nil {
			PayLoad = callback(PayLoad)
		}
		CheckTag := s["CheckTag"].(string)
		g.words = append(g.words, PayLoad)
		g.mapmode(Checktype(mytype), CheckTag, true)
	}
}

//GeneratorPayload 生成payload放入迭代器中，建议一个类型的标签只调用一次
/*
mode 标签模式
flag 随机数
payloaddata 加载的payload集
checktype 检测类型，生成的payload是以什么形式进行检测
extension 扩展类型
*/
func (g *Generator) GeneratorPayload(Tagmode int, flag string, payloaddata payload.PayloadData, extension interface{}) interface{} {
	g.flag = flag
	if Htmlmode == Tagmode {
		g.CopyPayLoadtoXSS(payloaddata, "html", nil)
	} else if Comment == Tagmode {
		g.CopyPayLoadtoXSS(payloaddata, "comment", nil)
	} else if Attibute == Tagmode {
		Occurences := extension.([]ast.Occurence)
		for _, Occurence := range Occurences {
			if funk.Contains(Occurence.Type, "key") {
				g.CopyPayLoadtoXSS(payloaddata, "html", nil)
			} else {
				//替换'<'和'>'为 url 编码
				if ok, _ := CheckHtmlNodeAttributes(Occurence, "key", "srcdoc", false); ok {
					g.CopyPayLoadtoXSS(payloaddata, "html", func(payload string) string {
						Lstr := strings.Replace(payload, "<", "%26lt;", -1)
						Rstr := strings.Replace(Lstr, ">", "%26gt;", -1)
						return Rstr
					})
				}
				//处理链接属性
				ok, _ := CheckHtmlNodeAttributes(Occurence, "key", "href", false)
				ok1, _ := CheckHtmlNodeAttributes(Occurence, "val", flag, false)
				if ok && ok1 {
					g.CopyPayLoadtoXSS(payloaddata, "script", func(payload string) string {
						Lstr := strings.Replace(payload, "<", "%26lt;", -1)
						Rstr := strings.Replace(Lstr, ">", "%26gt;", -1)
						return Rstr
					})
				}
				//处理onerror等on开头的属性情况
				if ok, Kv := CheckHtmlNodeAttributes(Occurence, "key", "on", true); ok {
					script := Kv.V.String()
					payload, err := ast.AnalyseJSFuncByFlag(flag, script)
					if err != nil {
						return err
					}
					log.Info("Attributes generator payload:%s", payload)
					g.words = append(g.words, payload)
					g.mapmode(CheckConsoleLog, "", false)
				}
				g.CopyPayLoadtoXSS(payloaddata, "html", func(payload string) string {
					Rstr := `'">` + payload
					return Rstr
				})
			}
		}

	} else if Script == Tagmode {
		Occurence := extension.(ast.Occurence)
		payload, err := ast.AnalyseJSFuncByFlag(flag, Occurence.Details.Content)
		if err != nil {
			return err
		}
		g.words = append(g.words, payload)
		g.mapmode(CheckConsoleLog, "", false)
	}
	return nil
}

//GetPayloadValue 迭代 payload
func (g *Generator) GetPayloadValue() (string, Checktype, string) {
	if g.Next() {
		if g.IsNeedFlag {
			switch v := g.Value().(type) {
			case string:
				v = strings.ReplaceAll(v, "flag", g.flag)
				return v, g.mode, g.Tag
			}
		} else {
			switch v := g.Value().(type) {
			case string:
				return v, g.mode, g.Tag
			}
		}
	}

	return "", "", ""
}

//CheckXssVul 检测Xss漏洞
func (g *Generator) evaluate(locations []ast.Occurence, methods Checktype, checktag string, extension interface{}) bool {
	var VulOK bool = false
	if len(locations) == 0 {
		return VulOK
	}
	if methods == CheckValue {
		for _, location := range locations {
			if checktag == location.Details.Tagname || checktag == "" {
				if location.Type == "attibute" {
					for _, Attributes := range *location.Details.Attributes {
						if Attributes.Key == g.flag || Attributes.Val == g.flag {
							VulOK = true
							break
						}
					}
				} else if location.Details.Content == g.flag {
					VulOK = true
					break
				}
			}

		}
	} else if methods == CheckTag {
		for _, location := range locations {
			if checktag == location.Details.Tagname || checktag == "" || location.Details.Tagname == "attibute" {
				if location.Type == "attibute" {
					for _, Attributes := range *location.Details.Attributes {
						if Attributes.Key == g.flag || Attributes.Val == g.flag {
							VulOK = true
							break
						}
					}
				} else if location.Details.Tagname == g.flag {
					VulOK = true
					break
				}
			}
		}
	}
	//判断执行的payload是否存在闭合标签，目前是用console.log(flag)要捕获控制台输出，你可以改别的好判断
	if methods == CheckConsoleLog {
		ev := extension.(*brohttp.Spider)
		select {
		case responseS := <-ev.Responses:
			for _, response := range responseS {
				if v, ok := response["log"]; ok {
					if v == g.flag {
						return true
					}
				}
			}
		case <-time.After(2 * time.Second):
			return false
		}
		return false

	}

	return VulOK
}

func DoCheckXss(ReponseInfo []map[int]interface{}, playload string, spider *brohttp.Spider) (*util.ScanResult, error) {
	g := new(Generator)

	payloadinfo := make(map[string]stf)
	payloadsdata, err := payload.LoadPayloadData("./xss.yaml")
	if err != nil {
		panic(err)
	}
	for _, v := range ReponseInfo {
		vlen := len(v)
		for i := 0; i < vlen; i++ {
			urlocc := v[i].(brohttp.UrlOCC)
			nodes := urlocc.OCC
			if len(nodes) != 0 {
				funk.Map(nodes, func(n ast.Occurence) interface{} {
					switch n.Type {
					case "html":
						g.GeneratorPayload(Htmlmode, playload, payloadsdata, nodes)
					case "attibute":
						g.GeneratorPayload(Attibute, playload, payloadsdata, nodes)
					case "script":
						g.GeneratorPayload(Script, playload, payloadsdata, nodes)
					}
					return false
				})
			}
		}
	}

	for {
		var htmls []string
		payload, Evalmode, tag := g.GetPayloadValue()
		if payload == "" {
			break
		}
		info := stf{mode: Evalmode, Tag: tag}
		payloadinfo[payload] = info
		//这里的map不是顺序执行
		for _, v := range ReponseInfo {
			vlen := len(v)
			for i := 0; i < vlen; i++ {
				urlocc := v[i].(brohttp.UrlOCC)
				// urlocc.Request.Data = payload
				spider.CopyRequest(urlocc.Request)
				response, _ := spider.CheckPayloadLocation(payload)
				htmls = append(htmls, response...)
			}
		}
		for _, html := range htmls {
			// fmt.Println(aurora.Red(html))
			for payload, checkfilter := range payloadinfo {
				Node := ast.SearchInputInResponse(playload, html)
				if len(Node) == 0 {
					break
				}
				if g.evaluate(Node, checkfilter.mode, checkfilter.Tag, spider) {
					Result := util.VulnerableTcpOrUdpResult(spider.Url.String(),
						"VULNERABLE to Cross-site scripting ...",
						[]string{string(payload)},
						[]string{string("")},
						"high")
					fmt.Println(aurora.Sprintf("检测Xss漏洞,Payload:%s", aurora.Red(payload)))
					return Result, err
				}
			}
		}
		htmls = []string{}
	}

	return nil, err
}

func CheckXss(args interface{}) (*util.ScanResult, error) {
	groups := args.(plugin.GroupData)
	Spider := groups.Spider
	var Result *util.ScanResult
	var err error
	if funk.Contains(groups.GroupType, "Button") || funk.Contains(groups.GroupType, "Submit") {
		flag := funk.RandomString(8)
		bflag := false
		resources := make([]map[int]interface{}, len(groups.GroupUrls))
		for _, Urlinfo := range groups.GroupUrls {
			Spider.CopyRequest(Urlinfo)
			println(Spider.Url.String())
			b, Occ := Spider.CheckRandOnHtmlS(flag)
			if b {
				bflag = true
			}
			resources = append(resources, Occ)
		}
		if !bflag {
			return nil, errors.New("not found")
		}
		Result, err = DoCheckXss(resources, flag, Spider)
		if err != nil {
			return nil, err
		}
	} else {
		flag := funk.RandomString(8)
		bflag := false
		resources := make([]map[int]interface{}, len(groups.GroupUrls))
		for _, Urlinfo := range groups.GroupUrls {
			Spider.CopyRequest(Urlinfo)
			b, Occ := Spider.CheckRandOnHtmlS(flag)
			if b {
				bflag = true
			}
			resources = append(resources, Occ)
		}
		if !bflag {
			return Result, errors.New("not found")
		}
		Result, err = DoCheckXss(resources, flag, Spider)
		if err != nil {
			return nil, err
		}
	}
	return Result, nil
}
