package crlf

import (
	"errors"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
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

	for _, pl := range payload_template {
		if strings.ToUpper(Param.Method) == "GET" {
			npl := Param.Url + pl
			req1, resp1, errs := sess.Get(npl, Param.Headers)
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
				Result := util.VulnerableTcpOrUdpResult(Param.Url,
					"CRLF Vulnerable",
					[]string{string(r)},
					[]string{resp1.String()},
					"middle",
					Param.Hostid)
				return Result, true, err
			}

		} else {
			req1, resp1, errs := sess.Post(Param.Url, Param.Headers, []byte(Param.Body+pl))
			if errs != nil {
				return nil, false, errs
			}

			// body := string(resp1.Body())
			Header_str := string(resp1.Header.Header())
			if str, _ := regexp.MatchString(RegexRule, Header_str); str {
				Result := util.VulnerableTcpOrUdpResult(Param.Url,
					"CRLF Vulnerable",
					[]string{string(req1.String())},
					[]string{resp1.String()},
					"middle",
					Param.Hostid)
				return Result, false, errs
			}
		}
	}

	return nil, false, err
}
