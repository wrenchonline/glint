package csrf

import (
	"fmt"
	"wenscan/fastreq"

	"github.com/logrusorgru/aurora"
	"github.com/valyala/fasthttp"
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

func Origin(k string, v []interface{}) error {
	ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	for _, url := range v {
		Req := fasthttp.AcquireRequest()
		err := fastreq.CopyConfReq(url, Req)
		if err != nil {
			return err
		}
		resp := &fasthttp.Response{}
		client := &fasthttp.Client{}
		if err := client.Do(Req, resp); err != nil {
			fmt.Println("request fail:", err.Error())
			return err
		}
		b1 := resp.Body()
		Req2 := fasthttp.AcquireRequest()
		Req.CopyTo(Req2)
		Req2.Header.Set("Origin", ORIGIN_URL)
		client2 := &fasthttp.Client{}
		if err := client2.Do(Req, resp); err != nil {
			fmt.Println("request fail:", err.Error())
			return err
		}
		b2 := resp.Body()
		if len(b1) == len(b2) {
			fmt.Println(aurora.Red("Heuristics reveal endpoint might be VULNERABLE to Origin Based CSRFs..."))
		}
	}
	return nil
}

func Referer(k string, v []interface{}) error {
	REFERER_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	for _, url := range v {
		Req := fasthttp.AcquireRequest()
		err := fastreq.CopyConfReq(url, Req)
		if err != nil {
			return err
		}
		resp := &fasthttp.Response{}
		client := &fasthttp.Client{}
		if err := client.Do(Req, resp); err != nil {
			fmt.Println("request fail:", err.Error())
			return err
		}
		b1 := resp.Body()
		Req2 := fasthttp.AcquireRequest()
		Req.CopyTo(Req2)
		Req2.Header.Set("Referer", REFERER_URL)
		client2 := &fasthttp.Client{}
		if err := client2.Do(Req, resp); err != nil {
			fmt.Println("request fail:", err.Error())
			return err
		}
		b2 := resp.Body()
		if len(b1) == len(b2) {
			fmt.Println(aurora.Red("Heuristics reveal endpoint might be VULNERABLE to Referer CSRFs..."))
		}
	}
	return nil
}
