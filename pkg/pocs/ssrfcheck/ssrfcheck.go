package ssrfcheck

import (
	"encoding/json"
	"errors"
	"glint/fastreq"
	"glint/logger"
	"glint/plugin"
	reverse2 "glint/reverse"
	"glint/util"
	"strings"
	"time"
)

var DefaultProxy = ""
var cert string
var mkey string

func Ssrf(args interface{}) (*util.ScanResult, bool, error) {
	util.Setup()
	group := args.(plugin.GroupData)
	// ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	ctx := *group.Pctx

	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	default:
	}

	session := group.GroupUrls.(map[string]interface{})
	url := session["url"].(string)
	method := session["method"].(string)
	headers, _ := util.ConvertHeaders(session["headers"].(map[string]interface{}))
	body := []byte(session["data"].(string))
	cert = group.HttpsCert
	mkey = group.HttpsCertKey
	sess := fastreq.GetSessionByOptions(
		&fastreq.ReqOptions{
			Timeout:       2 * time.Second,
			AllowRedirect: true,
			Proxy:         DefaultProxy,
			Cert:          cert,
			PrivateKey:    mkey,
		})

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

	params, err := util.ParseUri(url, body, method, ContentType)
	if err != nil {
		logger.Debug(err.Error())
		return nil, false, err
	}
	flag := util.RandLowLetterNumber(8)
	reverse := reverse2.NewReverse1(flag)
	_reverse := reverse.(*reverse2.Reverse1)
	payloads := params.SetPayload(url, _reverse.Url, method)
	logger.Debug("%v", payloads)

	if strings.ToUpper(method) == "POST" {
		for _, body := range payloads {
			req1, resp1, errs := sess.Post(url, headers, []byte(body))
			if errs != nil {
				return nil, false, errs
			}
			r1 := resp1.Body()
			if reverse2.ReverseCheck(reverse, 5) {
				Result := util.VulnerableTcpOrUdpResult(url,
					"ssrf Vulnerable",
					[]string{string(req1.String())},
					[]string{string(r1)},
					"middle",
					hostid)
				return Result, true, errs
			}
		}
		return nil, false, errors.New("params errors")
	} else {
		for _, uri := range payloads {
			req1, resp1, errs := sess.Get(uri, headers)
			if errs != nil {
				return nil, false, errs
			}
			r1 := resp1.Body()
			if reverse2.ReverseCheck(reverse, 5) {
				Result := util.VulnerableTcpOrUdpResult(url,
					"ssrf Vulnerable",
					[]string{string(req1.String())},
					[]string{string(r1)},
					"middle",
					hostid)
				return Result, true, errs
			}
		}
	}

	return nil, false, errors.New("params errors")
}
