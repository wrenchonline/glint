package csrf

import (
	"encoding/json"
	"errors"
	"fmt"
	"glint/fastreq"
	"glint/logger"
	"glint/plugin"
	"glint/util"
	"strings"

	"github.com/logrusorgru/aurora"
)

var anti_csrf = []string{
	// These are a list of known common tokens parameters
	"CSRFName",                   // OWASP CSRF_Guard
	"CSRFToken",                  // OWASP CSRF_Token
	"csrf_token",                 // PHP NoCSRF Class
	"anticsrf",                   // AntiCsrfParam.java
	"__RequestVerificationToken", // ASP.NET TokenParam
	"VerificationToken",          // AntiCSRFParam.java
	"form_build_id",              // Drupal CMS AntiCSRF
	"nonce",                      // WordPress Nonce
	"authenticity_token",         // Ruby on Rails
	"csrf_param",                 // Ruby on Rails
	"TransientKey",               // VanillaForums Param
	"csrf",                       // PHP CSRFProtect
	"AntiCSURF",                  // Anti CSURF (PHP)
	"YII_CSRF_TOKEN",             // http://www.yiiframework.com/
	"yii_anticsrf",               // http://www.yiiframework.com/
	"[_token]",                   // Symfony 2.x
	"_csrf_token",                // Symfony 1.4
	"csrfmiddlewaretoken",        // Django 1.5
	"ccm_token",                  // Concrete 5 CMS
	"XOOPS_TOKEN_REQUEST",        // Xoops CMS
	"_csrf",                      // Express JS Default Anti-CSRF
	"token",
	"auth",
	"hash",
	"secret",
	"verify",
}

// var DefaultProxy string = "127.0.0.1:7777"

var DefaultProxy string = ""
var cert string = ""
var mkey string = ""

func Csrfeval(args interface{}) (*util.ScanResult, error) {

	group := args.(plugin.GroupData)
	ORIGIN_URL := `http://192.168.166.8/vulnerabilities/csrf`
	// t := time.NewTimer(time.Millisecond * 200)
	ctx := *group.Pctx

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	session := group.GroupUrls.(map[string]interface{})
	url := session["url"].(string)
	// fmt.Printf("url: %s\n", url)
	method := session["method"].(string)
	headers, _ := util.ConvertHeaders(session["headers"].(map[string]interface{}))
	body := []byte(session["data"].(string))
	cert = group.HttpsCert
	mkey = group.HttpsCertKey

	var hostid int64
	if value, ok := session["hostid"].(int64); ok {
		hostid = value
	}

	if value, ok := session["hostid"].(json.Number); ok {
		hostid, _ = value.Int64()
	}

	var ContentType string = "None"
	if value, ok := headers["Content-Type"]; ok {
		ContentType = value
	}

	sess := fastreq.GetSessionByOptions(
		&fastreq.ReqOptions{
			Timeout:       2,
			AllowRedirect: true,
			Proxy:         DefaultProxy,
			Cert:          cert,
			PrivateKey:    mkey,
		})

	if strings.ToUpper(method) == "POST" {
		params, err := util.ParseUri(url, body, "POST", ContentType)
		if err != nil {
			logger.Error(err.Error())
			return nil, fmt.Errorf(err.Error())
		}
		if params.Len() == 0 {
			return nil, fmt.Errorf("post the url have no params")
		}

		_, resp1, errs := sess.Post(url, headers, []byte(body))
		if errs != nil {
			return nil, errs
		}
		b1 := resp1.Body()
		if resp1.StatusCode() != 200 {
			errstr := fmt.Sprintf("Fake Origin Response Fail. Status code: %d", resp1.StatusCode())
			return nil, errors.New(errstr)
		}
		headers["Origin"] = ORIGIN_URL
		req2, resp2, errs := sess.Post(url, headers, []byte(body))
		b2 := resp2.Body()
		if len(b1) == len(b2) {
			fmt.Println(aurora.Red("Heuristics reveal endpoint might be VULNERABLE to Origin Base CSRFs..."))
			Result := util.VulnerableTcpOrUdpResult(url,
				"csrf Origin Vulnerable",
				[]string{string(req2.String())},
				[]string{string(b2)},
				"middle",
				hostid)
			return Result, errs
		}

		REFERER_URL := `http://192.168.166.8/vulnerabilities/csrf`
		ctx := *group.Pctx
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		_, resp1, errs = sess.Post(url, headers, []byte(body))
		if errs != nil {
			return nil, errs
		}
		b1 = resp1.Body()
		if resp1.StatusCode() != 200 {
			errstr := fmt.Sprintf("Fake Origin Referer Fail. Status code: %d", resp1.StatusCode())
			return nil, errors.New(errstr)
		}
		headers["Referer"] = REFERER_URL
		req2, resp2, errs = sess.Post(url, headers, []byte(body))
		b2 = resp2.Body()
		if len(b1) == len(b2) {
			logger.Debug("Heuristics reveal endpoint might be VULNERABLE to Referer CSRFs...")
			Result := util.VulnerableTcpOrUdpResult(url,
				"Heuristics reveal endpoint might be VULNERABLE to Referer CSRFs...",
				[]string{string(req2.String())},
				[]string{string(b2)},
				"middle",
				hostid)
			return Result, errs
		}
		return nil, errs

	}

	return nil, errors.New("these is get method or params errors")
}

// func Referer(args interface{}) (*util.ScanResult, error) {

// 	return nil, errors.New("these is get method or params errors")
// }
