package csrf

import (
	"errors"
	"fmt"
	"glint/fastreq"
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

var DefaultProxy string = "127.0.0.1:8080"

func Origin(k string, v []interface{}) error {
	ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	for _, s := range v {
		session := s.(map[string]interface{})
		url := session["url"].(string)
		method := session["method"].(string)
		headers := util.ConvertHeaders(session["headers"].(map[string]interface{}))
		body := []byte(session["data"].(string))
		if strings.ToUpper(method) == "POST" {
			resp1, errs := fastreq.Post(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy}, body)
			b1 := resp1.Body()
			if resp1.StatusCode() != 200 {
				errstr := fmt.Sprintf("Fake Origin Response Fail. Status code: %d", resp1.StatusCode())
				return errors.New(errstr)
			}
			headers["Origin"] = ORIGIN_URL
			resp2, errs := fastreq.Post(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy}, body)
			b2 := resp2.Body()
			if len(b1) == len(b2) {
				fmt.Println(aurora.Red("Heuristics reveal endpoint might be VULNERABLE to Origin Base CSRFs..."))
			}
			return errs
		} else {
			resp1, errs := fastreq.Get(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy})
			b1 := resp1.Body()
			if resp1.StatusCode() != 200 {
				errstr := fmt.Sprintf("Fake Origin Response Fail. Status code: %d", resp1.StatusCode())
				return errors.New(errstr)
			}
			headers["Origin"] = ORIGIN_URL
			resp2, errs := fastreq.Get(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy})
			b2 := resp2.Body()
			if len(b1) == len(b2) {
				fmt.Println(aurora.Red("Heuristics reveal endpoint might be VULNERABLE to Origin Base CSRFs..."))
			}
			return errs
		}
	}
	return nil
}

func Referer(k string, v []interface{}) error {
	REFERER_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	for _, s := range v {
		session := s.(map[string]interface{})
		url := session["url"].(string)
		method := session["method"].(string)
		headers := util.ConvertHeaders(session["headers"].(map[string]interface{}))
		body := []byte(session["data"].(string))
		if strings.ToUpper(method) == "POST" {
			resp1, errs := fastreq.Post(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy}, body)
			b1 := resp1.Body()
			if resp1.StatusCode() != 200 {
				errstr := fmt.Sprintf("Fake Origin Referer Fail. Status code: %d", resp1.StatusCode())
				return errors.New(errstr)
			}
			headers["Referer"] = REFERER_URL
			resp2, errs := fastreq.Post(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy}, body)
			b2 := resp2.Body()
			if len(b1) == len(b2) {
				fmt.Println(aurora.Red("Heuristics reveal endpoint might be VULNERABLE to Referer CSRFs..."))
			}
			return errs
		} else {
			resp1, errs := fastreq.Get(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy})
			b1 := resp1.Body()
			if resp1.StatusCode() != 200 {
				errstr := fmt.Sprintf("Fake Origin Referer Fail. Status code: %d", resp1.StatusCode())
				return errors.New(errstr)
			}
			headers["Referer"] = REFERER_URL
			resp2, errs := fastreq.Get(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy})
			b2 := resp2.Body()
			if len(b1) == len(b2) {
				fmt.Println(aurora.Red("Heuristics reveal endpoint might be VULNERABLE to Referer CSRFs..."))
			}
			return errs
		}
	}
	return nil
}
