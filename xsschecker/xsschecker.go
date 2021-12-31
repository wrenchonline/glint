package xsschecker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"glint/ast"
	"glint/brohttp"
	"glint/logger"
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
	extension  []PayloadMode
	flag       string
}

func (g *Generator) Next() bool {
	if g.i == len(g.extension) {
		return false
	}
	g.value = g.extension[g.i].payload
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
		logger.Debug("ok")
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
		var mode PayloadMode
		mode.Mode = Checktype(mytype)
		mode.IsNeedFlag = true
		mode.payload = PayLoad
		mode.CheckTag = CheckTag
		g.extension = append(g.extension, mode)
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
	var (
		htmlok     bool
		attibuteoK bool
		CommentoK  bool
		scriptok   bool
	)
	if Htmlmode == Tagmode {
		if !htmlok {
			g.CopyPayLoadtoXSS(payloaddata, "html", nil)
			htmlok = true
		}

	} else if Comment == Tagmode {
		if !CommentoK {
			g.CopyPayLoadtoXSS(payloaddata, "comment", nil)
			CommentoK = true
		}

	} else if Attibute == Tagmode {
		Occurences := extension.([]ast.Occurence)
		for _, Occurence := range Occurences {
			if funk.Contains(Occurence.Type, "key") {
				g.CopyPayLoadtoXSS(payloaddata, "html", nil)
			} else {
				//替换'<'和'>'为 url 编码
				// if ok, _ := CheckHtmlNodeAttributes(Occurence, "key", "srcdoc", false); ok {
				// 	g.CopyPayLoadtoXSS(payloaddata, "html", func(payload string) string {
				// 		Lstr := strings.Replace(payload, "<", "%26lt;", -1)
				// 		Rstr := strings.Replace(Lstr, ">", "%26gt;", -1)
				// 		return Rstr
				// 	})
				// }
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
					logger.Info("Attributes generator payload:%s", payload)
					var mode PayloadMode
					mode.Mode = Checktype(CheckConsoleLog)
					mode.IsNeedFlag = true
					mode.payload = payload
					mode.CheckTag = ""
					g.extension = append(g.extension, mode)
				}
				if !attibuteoK {
					g.CopyPayLoadtoXSS(payloaddata, "html", func(payload string) string {
						Rstr := `'">` + payload
						return Rstr
					})
					attibuteoK = true
				}
			}
		}

	} else if Script == Tagmode {
		if !scriptok {
			Occurence := extension.(ast.Occurence)
			payload, err := ast.AnalyseJSFuncByFlag(flag, Occurence.Details.Content)
			if err != nil {
				return err
			}
			var mode PayloadMode
			mode.Mode = Checktype(CheckConsoleLog)
			mode.IsNeedFlag = true
			mode.payload = payload
			mode.CheckTag = ""
			g.extension = append(g.extension, mode)
			scriptok = true
		}
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

type xssOcc struct {
	Url   string
	Htmls []string
}

func DoCheckXss(GroupUrlsReponseInfo []map[int]interface{}, playload string, spider *brohttp.Spider, ctx context.Context) (*util.ScanResult, error) {
	g := new(Generator)
	var (
		htmlok     bool
		attibuteoK bool
		scriptok   bool
	)
	// t := time.NewTimer(time.Millisecond * 200)
	payloadsdata, err := payload.LoadPayloadData("./xss.yaml")
	if err != nil {
		return nil, errors.New("empty to xss payload ")
	}
	// for _, v := range GroupUrlsReponseInfo {
	// 	vlen := len(v)
	// 	for i := 0; i < vlen; i++ {

	// 	}
	// }
	var Occs []xssOcc
	payloadinfo := make(map[string]stf)

	//这里的map不是顺序执行
	for _, v := range GroupUrlsReponseInfo {
		select {
		case <-ctx.Done():
			// t.Stop()
			return nil, ctx.Err()
		default:
		}

		vlen := len(v)
		for i := 0; i < vlen; i++ {
			urlocc := v[i].(brohttp.UrlOCC)
			nodes := urlocc.OCC
			logger.Info("url %s nodes %d", urlocc.Request.Url, len(nodes))
			if len(nodes) != 0 {
				funk.Map(nodes, func(n ast.Occurence) interface{} {
					switch n.Type {
					case "html":
						if !htmlok {
							g.GeneratorPayload(Htmlmode, playload, payloadsdata, nodes)
							htmlok = true
						}
					case "attibute":
						if !attibuteoK {
							g.GeneratorPayload(Attibute, playload, payloadsdata, nodes)
							attibuteoK = true
						}
					case "script":
						if !scriptok {
							g.GeneratorPayload(Script, playload, payloadsdata, nodes)
							scriptok = true
						}

					}
					return false
				})
			}

			for {
				payload, Evalmode, tag := g.GetPayloadValue()
				if payload == "" {
					break
				}
				info := stf{mode: Evalmode, Tag: tag}
				payloadinfo[payload] = info
				urlocc := v[i].(brohttp.UrlOCC)
				if len(urlocc.OCC) > 0 {
					logger.Warning("xss eval  url: %s payload: %s", urlocc.Request.Url, payload)
					spider.CopyRequest(urlocc.Request)
					response, _ := spider.CheckPayloadLocation(payload)
					occ := xssOcc{Url: urlocc.Request.Url, Htmls: response}
					Occs = append(Occs, occ)
				}
			}
		}
	}

	for _, occ := range Occs {
		for _, html := range occ.Htmls {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			// fmt.Println(aurora.html))
			for payload, checkfilter := range payloadinfo {
				Node := ast.SearchInputInResponse(playload, html)
				if len(Node) == 0 {
					break
				}
				if g.evaluate(Node, checkfilter.mode, checkfilter.Tag, spider) {

					Result := util.VulnerableTcpOrUdpResult(occ.Url,
						"VULNERABLE to Cross-site scripting ...",
						[]string{string(payload)},
						[]string{string("")},
						"high")
					fmt.Println(aurora.Sprintf("检测Xss漏洞,Payload:%s", aurora.Red(payload)))
					return Result, err
				}
			}
		}
	}

	return nil, errors.New("no found xss vulnerabilities")
}

func CheckXss(args interface{}) (*util.ScanResult, error) {
	groups := args.(plugin.GroupData)
	Spider := groups.Spider

	ctx := groups.Pctx
	var Result *util.ScanResult
	var err error

	if _, ok := (*Spider.Ctx).Deadline(); ok {
		logger.Warning("xss spider is dead")
		goto quit
	}
	if funk.Contains(groups.GroupType, "Button") || funk.Contains(groups.GroupType, "Submit") {
		flag := funk.RandomString(8)
		bflag := false
		resources := make([]map[int]interface{}, len(groups.GroupUrls))
		for _, Urlinfo := range groups.GroupUrls {
			Spider.CopyRequest(Urlinfo)
			// println("pre", Spider.Url.String())
			b, Occ := Spider.CheckRandOnHtmlS(flag, Urlinfo)
			// Spider.CopyRequest(Urlinfo)
			// println("post", Spider.Url.String())
			if b {
				bflag = true
			}
			resources = append(resources, Occ)
		}
		if !bflag {
			return nil, errors.New("xss:: not found")
		}
		Result, err = DoCheckXss(resources, flag, Spider, *ctx)
		if err != nil {
			return nil, err
		}
	} else {
		flag := funk.RandomString(8)
		bflag := false
		resources := make([]map[int]interface{}, len(groups.GroupUrls))
		for _, Urlinfo := range groups.GroupUrls {
			Spider.CopyRequest(Urlinfo)
			println("pre", Spider.Url.String())
			b, Occ := Spider.CheckRandOnHtmlS(flag, Urlinfo)
			if b {
				bflag = true
			}
			resources = append(resources, Occ)
		}
		if !bflag {
			return Result, errors.New("xss::not found")
		}

		Result, err = DoCheckXss(resources, flag, Spider, *ctx)
		if err != nil {
			return nil, err
		}
	}
quit:
	return Result, nil
}
