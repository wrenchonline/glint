package jsonp

import (
	"errors"
	"fmt"
	"glint/fastreq"
	"glint/logger"
	"glint/plugin"
	"glint/util"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"github.com/valyala/fasthttp"
)

type Jsonpinfo struct {
	Request  *fasthttp.Request
	Response *fasthttp.Response
}

func CheckSenseJsonp(jsUrl string, headers map[string]string) (bool, *Jsonpinfo, error) {
	queryMap, _, err := UrlParser(jsUrl)
	if err != nil {
		return false, nil, err
	}

	isCallback, callbackFuncName, err := CheckJSIsCallback(queryMap)
	if err != nil {
		return false, nil, err
	}
	if isCallback {
		//	referer： host 请求
		normalRespContent, _, err := GetJsResponse(jsUrl, headers)
		if err != nil {
			return false, nil, err
		}
		isJsonpNormal, err := CheckJsRespAst(normalRespContent, callbackFuncName)
		if err != nil {
			return false, nil, err
		}
		// 如果包含敏感字段 将 referer 置空 再请求一次
		if isJsonpNormal {
			headers["Referer"] = ""
			noRefererContent, info, err := GetJsResponse(jsUrl, headers)
			if err != nil {
				return false, nil, err
			}
			isJsonp, err := CheckJsRespAst(noRefererContent, callbackFuncName)
			if err != nil {
				return false, nil, err
			}
			return isJsonp, info, nil
		}

	}
	return false, nil, nil
}

func UrlParser(jsUrl string) (url.Values, string, error) {
	urlParser, err := url.Parse(jsUrl)
	if err != nil {
		return nil, "", err
	}
	// 拼接原始referer
	domainString := urlParser.Scheme + "://" + urlParser.Host
	return urlParser.Query(), domainString, nil
}

func CheckJSIsCallback(queryMap url.Values) (bool, string, error) {
	var re = regexp.MustCompile(`(?m)(?i)(callback)|(jsonp)|(^cb$)|(function)`)
	for k, v := range queryMap {
		regResult := re.FindAllString(k, -1)
		if len(regResult) > 0 && len(v) > 0 {
			return true, v[0], nil
		}
	}
	return false, "", nil
}

func CheckIsSensitiveKey(key string) (bool, error) {
	var re = regexp.MustCompile(`(?m)(?i)(uid)|(userid)|(user_id)|(nin)|(name)|(username)|(nick)`)
	regResult := re.FindAllString(key, -1)
	if len(regResult) > 0 {
		return true, nil
	}
	return false, nil
}

func GetJsResponse(jsUrl string, headers map[string]string) (string, *Jsonpinfo, error) {
	req1, resp1, err := fastreq.Get(jsUrl, headers,
		&fastreq.ReqOptions{Timeout: 2, AllowRedirect: false, Proxy: DefaultProxy})
	if err != nil {
		return "", nil, nil
	}
	if resp1.StatusCode() != 200 {
		errstr := fmt.Sprintf("Fake Origin Referer Fail. Status code: %d", resp1.StatusCode())
		return "", nil, errors.New(errstr)
	}

	r1 := resp1.Body()
	info := Jsonpinfo{
		Request:  req1,
		Response: &resp1.Response,
	}
	return string(r1), &info, nil
}

func CheckJsRespAst(content string, funcName string) (bool, error) {
	// var params = []string{}
	// var vardiscover bool
	var Valid_Callback bool = false
	var Valid_Key bool = false

	obj := js.Options{}
	ast, err := js.Parse(parse.NewInputString(content), obj)
	if err != nil {
		return false, err
	}

	logger.Debug("Scope:%s", ast.Scope.String())
	logger.Debug("JS:%s", ast.String())
	//ast.BlockStmt.String()
	l := js.NewLexer(parse.NewInputString(content))
	for {
		tt, text := l.Next()
		//fmt.Println("text", string(text))
		switch tt {
		case js.ErrorToken:
			if l.Err() != io.EOF {
				fmt.Println("Error on line:", l.Err())
			}
			return Valid_Key, nil
		case js.VarToken:
			// vardiscover = true
		case js.StringToken:
			if Valid_Callback {
				bexist, err := CheckIsSensitiveKey(string(text))
				if err != nil {
					return false, err
				}
				if bexist {
					Valid_Key = true
				}
			}
		case js.IdentifierToken:
			Identifier := string(text)
			//fmt.Println("IdentifierToken", Identifier)
			if Identifier == funcName {
				Valid_Callback = true
			}
		}
	}
	// return false, nil
}

var DefaultProxy = ""

func JsonpValid(args interface{}) (*util.ScanResult, error) {
	group := args.(plugin.GroupData)
	// ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	ctx := *group.Pctx

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	session := group.GroupUrls.(map[string]interface{})
	url := session["url"].(string)
	method := session["method"].(string)
	if strings.ToUpper(method) != "GET" {
		return nil, nil
	}
	headers, _ := util.ConvertHeaders(session["headers"].(map[string]interface{}))
	isvul, info, err := CheckSenseJsonp(url, headers)
	if err != nil {
		return nil, fmt.Errorf("check jsonp error: %v", err)
	}

	if isvul {
		Result := util.VulnerableTcpOrUdpResult(url,
			"jsonp vulnerability found",
			[]string{string(info.Request.String())},
			[]string{string(info.Response.String())},
			"middle",
			session["hostid"].(int64))
		return Result, err
	}
	return nil, errors.New("jsonp vulnerability not found")
}
