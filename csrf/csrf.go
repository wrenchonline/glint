package csrf

import (
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
	"CSRFToken",                  // OWASP CSRF_Guard
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

func Origin(args interface{}) (*util.ScanResult, error) {
	group := args.(plugin.GroupData)
	ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	// t := time.NewTimer(time.Millisecond * 200)
	ctx := *group.Pctx

	for _, s := range group.GroupUrls {
		select {
		case <-ctx.Done():
			// t.Stop()
			return nil, ctx.Err()
		default:
		}
		session := s.(map[string]interface{})
		url := session["url"].(string)
		method := session["method"].(string)
		headers := util.ConvertHeaders(session["headers"].(map[string]interface{}))
		body := []byte(session["data"].(string))
		if strings.ToUpper(method) == "POST" {
			_, resp1, errs := fastreq.Post(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy}, body)
			if errs != nil {
				return nil, errs
			}
			b1 := resp1.Body()
			if resp1.StatusCode() != 200 {
				errstr := fmt.Sprintf("Fake Origin Response Fail. Status code: %d", resp1.StatusCode())
				return nil, errors.New(errstr)
			}
			headers["Origin"] = ORIGIN_URL
			req2, resp2, errs := fastreq.Post(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy}, body)
			b2 := resp2.Body()
			if len(b1) == len(b2) {
				fmt.Println(aurora.Red("Heuristics reveal endpoint might be VULNERABLE to Origin Base CSRFs..."))
				Result := util.VulnerableTcpOrUdpResult(url,
					"csrf Origin Vulnerable",
					[]string{string(req2.String())},
					[]string{string(b2)},
					"middle")
				return Result, errs
			}
			return nil, errors.New("params errors")
		} else {
			_, resp1, errs := fastreq.Get(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy})
			if errs != nil {
				return nil, errs
			}
			b1 := resp1.Body()
			if resp1.StatusCode() != 200 {
				errstr := fmt.Sprintf("Fake Origin Response Fail. Status code: %d", resp1.StatusCode())
				return nil, errors.New(errstr)
			}
			headers["Origin"] = ORIGIN_URL
			req2, resp2, errs := fastreq.Get(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy})
			if errs != nil {
				return nil, errs
			}
			b2 := resp2.Body()
			if len(b1) == len(b2) {
				logger.Debug("Heuristics reveal endpoint might be VULNERABLE to Origin Base CSRFs...")
				Result := util.VulnerableTcpOrUdpResult(url,
					"Heuristics reveal endpoint might be VULNERABLE to Origin Base CSRFs...",
					[]string{string(req2.String())},
					[]string{string(b2)},
					"middle")
				return Result, errs
			}

		}
	}
	return nil, errors.New("params errors")
}

func Referer(args interface{}) (*util.ScanResult, error) {
	group := args.(plugin.GroupData)
	REFERER_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	ctx := *group.Pctx

	for _, s := range group.GroupUrls {
		select {
		case <-ctx.Done():

			return nil, ctx.Err()
		default:
		}
		session := s.(map[string]interface{})
		url := session["url"].(string)
		method := session["method"].(string)
		headers := util.ConvertHeaders(session["headers"].(map[string]interface{}))
		body := []byte(session["data"].(string))
		if strings.ToUpper(method) == "POST" {
			_, resp1, errs := fastreq.Post(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy}, body)
			if errs != nil {
				return nil, errs
			}
			b1 := resp1.Body()
			if resp1.StatusCode() != 200 {
				errstr := fmt.Sprintf("Fake Origin Referer Fail. Status code: %d", resp1.StatusCode())
				return nil, errors.New(errstr)
			}
			headers["Referer"] = REFERER_URL
			req2, resp2, errs := fastreq.Post(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy}, body)
			b2 := resp2.Body()
			if len(b1) == len(b2) {
				logger.Debug("Heuristics reveal endpoint might be VULNERABLE to Referer CSRFs...")
				Result := util.VulnerableTcpOrUdpResult(url,
					"Heuristics reveal endpoint might be VULNERABLE to Referer CSRFs...",
					[]string{string(req2.String())},
					[]string{string(b2)},
					"middle")
				return Result, errs
			}
			return nil, errs
		} else {
			_, resp1, errs := fastreq.Get(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy})
			if errs != nil {
				return nil, errs
			}
			b1 := resp1.Body()
			if resp1.StatusCode() != 200 {
				errstr := fmt.Sprintf("Fake Origin Referer Fail. Status code: %d", resp1.StatusCode())
				return nil, errors.New(errstr)
			}
			headers["Referer"] = REFERER_URL
			req2, resp2, errs := fastreq.Get(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy})
			if errs != nil {
				return nil, errs
			}
			b2 := resp2.Body()
			if len(b1) == len(b2) {
				fmt.Println(aurora.Red("Heuristics reveal endpoint might be VULNERABLE to Referer CSRFs..."))
				Result := util.VulnerableTcpOrUdpResult(url,
					"Heuristics reveal endpoint might be VULNERABLE to Referer CSRFs...",
					[]string{string(req2.String())},
					[]string{string(b2)},
					"middle")
				return Result, errs
			}
			return nil, errs
		}
	}
	return nil, errors.New("params errors")
}
