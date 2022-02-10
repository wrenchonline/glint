package ssrfcheck

import (
	"errors"
	"glint/fastreq"
	"glint/logger"
	"glint/plugin"
	reverse2 "glint/reverse"
	"glint/util"
	"strings"
)

var DefaultProxy = ""

func Ssrf(args interface{}) (*util.ScanResult, error) {
	util.Setup()
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
	headers := util.ConvertHeaders(session["headers"].(map[string]interface{}))
	body := []byte(session["data"].(string))

	var ContentType string = "None"
	if value, ok := headers["Content-Type"]; ok {
		ContentType = value
	}

	params, err := util.ParseUri(url, body, method, ContentType)
	if err != nil {
		logger.Error(err.Error())
	}

	reverse := reverse2.NewReverse1()
	_reverse := reverse.(*reverse2.Reverse1)
	payloads := params.SetPayload(url, _reverse.Url, method)
	logger.Debug("%v", payloads)

	if strings.ToUpper(method) == "POST" {
		for _, body := range payloads {
			req1, resp1, errs := fastreq.Post(url, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy}, []byte(body))
			if errs != nil {
				return nil, errs
			}
			r1 := resp1.Body()
			if reverse2.ReverseCheck(reverse, 5) {
				Result := util.VulnerableTcpOrUdpResult(url,
					"ssrf Vulnerable",
					[]string{string(req1.String())},
					[]string{string(r1)},
					"middle")
				return Result, errs
			}
		}
		return nil, errors.New("params errors")
	} else {
		for _, uri := range payloads {
			req1, resp1, errs := fastreq.Get(uri, headers,
				&fastreq.ReqOptions{Timeout: 2, AllowRedirect: true, Proxy: DefaultProxy})
			if errs != nil {
				return nil, errs
			}
			r1 := resp1.Body()
			if reverse2.ReverseCheck(reverse, 5) {
				Result := util.VulnerableTcpOrUdpResult(url,
					"ssrf Vulnerable",
					[]string{string(req1.String())},
					[]string{string(r1)},
					"middle")
				return Result, errs
			}
		}
	}

	return nil, errors.New("params errors")
}
