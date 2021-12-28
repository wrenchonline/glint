package ssrfcheck

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

var DefaultProxy = ""

func SSRF(args interface{}) (*util.ScanResult, error) {
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
