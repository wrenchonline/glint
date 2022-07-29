package jsonp

import (
	"errors"
	"fmt"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"github.com/valyala/fasthttp"
)

var cert string
var mkey string

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

	sess := nenet.GetSessionByOptions(
		&nenet.ReqOptions{
			Timeout:       2 * time.Second,
			AllowRedirect: true,
			Proxy:         DefaultProxy,
			Cert:          cert,
			PrivateKey:    mkey,
		})

	req1, resp1, err := sess.Get(jsUrl, headers)
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
		Response: resp1,
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

func JsonpValid(args interface{}) (*util.ScanResult, bool, error) {
	util.Setup()
	var Param layers.PluginParam
	ct := layers.CheckType{}
	Param.ParsePluginParams(args.(plugin.GroupData), ct)
	if Param.CheckForExitSignal() {
		return nil, false, errors.New("receive task exit signal")
	}

	// sess := nenet.GetSessionByOptions(
	// 	&nenet.ReqOptions{
	// 		Timeout:       time.Duration(Param.Timeout) * time.Second,
	// 		AllowRedirect: false,
	// 		Proxy:         Param.UpProxy,
	// 		Cert:          Param.Cert,
	// 		PrivateKey:    Param.CertKey,
	// 	})

	if strings.ToUpper(Param.Method) != "GET" {
		return nil, false, nil
	}

	isvul, info, err := CheckSenseJsonp(Param.Url, Param.Headers)
	if err != nil {
		return nil, false, fmt.Errorf("check jsonp error: %v", err)
	}

	if isvul {
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"jsonp vulnerability found",
			[]string{string(info.Request.String())},
			[]string{string(info.Response.String())},
			"middle",
			Param.Hostid)
		return Result, true, err
	}
	return nil, false, errors.New("jsonp vulnerability not found")
}
