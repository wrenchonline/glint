package csrf

import (
	"errors"
	"fmt"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"strings"
	"time"

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

func Csrfeval(args interface{}) (*util.ScanResult, bool, error) {

	group := args.(plugin.GroupData)
	ORIGIN_URL := `http://192.168.166.8/vulnerabilities/csrf`
	// t := time.NewTimer(time.Millisecond * 200)
	var Param layers.PluginParam
	ct := layers.CheckType{}
	Param.ParsePluginParams(args.(plugin.GroupData), ct)
	if Param.CheckForExitSignal() {
		return nil, false, errors.New("receive task exit signal")
	}

	sess := nenet.GetSessionByOptions(
		&nenet.ReqOptions{
			Timeout:       time.Duration(Param.Timeout) * time.Second,
			AllowRedirect: false,
			Proxy:         Param.UpProxy,
			Cert:          Param.Cert,
			PrivateKey:    Param.CertKey,
		})

	var ContentType string = "None"
	if value, ok := Param.Headers["Content-Type"]; ok {
		ContentType = value
	}

	if strings.ToUpper(Param.Method) == "POST" {
		params, err := util.ParseUri(Param.Url, []byte(Param.Body), "POST", ContentType)
		if err != nil {
			logger.Debug(err.Error())
			return nil, false, fmt.Errorf(err.Error())
		}
		if params.Len() == 0 {
			return nil, false, fmt.Errorf("post the url have no params")
		}

		_, resp1, errs := sess.Post(Param.Url, Param.Headers, []byte(Param.Body))
		if errs != nil {
			return nil, false, errs
		}
		b1 := resp1.Body()
		if resp1.StatusCode() != 200 {
			errstr := fmt.Sprintf("Fake Origin Response Fail. Status code: %d", resp1.StatusCode())
			return nil, false, errors.New(errstr)
		}
		Param.Headers["Origin"] = ORIGIN_URL
		req2, resp2, errs := sess.Post(Param.Url, Param.Headers, []byte(Param.Body))
		b2 := resp2.Body()
		if len(b1) == len(b2) {
			fmt.Println(aurora.Red("Heuristics reveal endpoint might be VULNERABLE to Origin Base CSRFs..."))
			Result := util.VulnerableTcpOrUdpResult(Param.Url,
				"csrf Origin Vulnerable",
				[]string{string(req2.String())},
				[]string{string(b2)},
				"middle",
				Param.Hostid)
			return Result, true, errs
		}

		REFERER_URL := `http://192.168.166.8/vulnerabilities/csrf`
		ctx := *group.Pctx
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		default:
		}
		_, resp1, errs = sess.Post(Param.Url, Param.Headers, []byte(Param.Body))
		if errs != nil {
			return nil, false, errs
		}
		b1 = resp1.Body()
		if resp1.StatusCode() != 200 {
			errstr := fmt.Sprintf("Fake Origin Referer Fail. Status code: %d", resp1.StatusCode())
			return nil, false, errors.New(errstr)
		}
		Param.Headers["Referer"] = REFERER_URL
		req2, resp2, errs = sess.Post(Param.Url, Param.Headers, []byte(Param.Body))
		b2 = resp2.Body()
		if len(b1) == len(b2) {
			logger.Debug("Heuristics reveal endpoint might be VULNERABLE to Referer CSRFs...")
			Result := util.VulnerableTcpOrUdpResult(Param.Url,
				"Heuristics reveal endpoint might be VULNERABLE to Referer CSRFs...",
				[]string{string(req2.String())},
				[]string{string(b2)},
				"middle",
				Param.Hostid)
			return Result, true, errs
		}
		return nil, false, errs

	}

	return nil, false, errors.New("these is get method or params errors")
}

// func Referer(args interface{}) (*util.ScanResult, error) {

// 	return nil, errors.New("these is get method or params errors")
// }
