package crlf

import (
	"encoding/json"
	"glint/fastreq"
	"glint/logger"
	"glint/plugin"
	"glint/util"
	"regexp"
	"strings"
	"time"
)

var DefaultProxy = ""
var cert string
var mkey string

const (
	RegexRule = `(?i)[\n|\r](Somecustominjectedheader\s*:\s*injected_by_wvs)`
)

//crlfCheck
var payload_template = []string{
	`/%0ASomecustominjectedheader: injected_by_wvs`,
	`\r\nSomeCustomInjectedHeader: injected_by_wvs`,
	`\r\n\tSomeCustomInjectedHeader: injected_by_wvs`,
	`\r\n SomeCustomInjectedHeader: injected_by_wvs`,
	`\r\tSomeCustomInjectedHeader: injected_by_wvs`,
	`\nSomeCustomInjectedHeader: injected_by_wvs`,
	`\rSomeCustomInjectedHeader: injected_by_wvs`,
	`\rSomeCustomInjectedHeader: injected_by_wvs`,
	`%E5%98%8A%E5%98%8DSomeCustomInjectedHeader:%20injected_by_wvs`,
	`%c4%8d%c4%8aSomeCustomInjectedHeader:%20injected_by_wvs`,
}

func Crlf(args interface{}) (*util.ScanResult, bool, error) {
	var err error
	var hostid int64
	// var buf bufio{}
	// var blastIters interface{}
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
	Body := session["data"].(string)
	cert = group.HttpsCert
	mkey = group.HttpsCertKey
	sess := fastreq.GetSessionByOptions(
		&fastreq.ReqOptions{
			Timeout:       2 * time.Second,
			AllowRedirect: false,
			Proxy:         DefaultProxy,
			Cert:          cert,
			PrivateKey:    mkey,
		})

	if value, ok := session["hostid"].(int64); ok {
		hostid = value
	}

	if value, ok := session["hostid"].(json.Number); ok {
		hostid, _ = value.Int64()
	}

	// var ContentType string = "None"
	// if value, ok := headers["Content-Type"]; ok {
	// 	ContentType = value
	// }

	for _, pl := range payload_template {
		if strings.ToUpper(method) == "GET" {
			npl := url + pl
			req1, resp1, errs := sess.Get(npl, headers)
			if errs != nil {
				return nil, false, errs
			}

			Text := string(resp1.Header.Header())
			//logger.Inf("%s", Text)
			// println(Text)
			r, err := regexp.Compile(RegexRule)
			if err != nil {
				logger.Debug("%s", err.Error())
				return nil, false, errs
			}

			C := r.FindAllStringSubmatch(Text, -1)
			if len(C) != 0 {
				r := req1.String()
				Result := util.VulnerableTcpOrUdpResult(url,
					"CRLF Vulnerable",
					[]string{string(r)},
					[]string{resp1.String()},
					"middle",
					hostid)
				return Result, true, err
			}

		} else {
			req1, resp1, errs := sess.Post(url, headers, []byte(Body+pl))
			if errs != nil {
				return nil, false, errs
			}

			// body := string(resp1.Body())
			Header_str := string(resp1.Header.Header())
			if str, _ := regexp.MatchString(RegexRule, Header_str); str {
				Result := util.VulnerableTcpOrUdpResult(url,
					"CRLF Vulnerable",
					[]string{string(req1.String())},
					[]string{resp1.String()},
					"middle",
					session["hostid"].(int64))
				return Result, false, errs
			}
		}
	}

	return nil, false, err
}
