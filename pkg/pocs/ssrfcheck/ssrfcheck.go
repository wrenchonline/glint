package ssrfcheck

import (
	"errors"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	reverse2 "glint/reverse"
	"glint/util"
	"strings"
	"time"
)

func Ssrf(args interface{}) (*util.ScanResult, bool, error) {
	util.Setup()
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

	params, err := util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType)
	if err != nil {
		logger.Debug(err.Error())
		return nil, false, err
	}
	flag := util.RandLowLetterNumber(8)
	reverse := reverse2.NewReverse1(flag)
	_reverse := reverse.(*reverse2.Reverse1)
	payloads := params.SetPayload(Param.Url, _reverse.Url, Param.Method)
	logger.Debug("%v", payloads)

	if strings.ToUpper(Param.Method) == "POST" {
		for _, body := range payloads {
			req1, resp1, errs := sess.Post(Param.Url, Param.Headers, []byte(body))
			if errs != nil {
				return nil, false, errs
			}
			r1 := resp1.Body()
			if reverse2.ReverseCheck(reverse, 5) {
				Result := util.VulnerableTcpOrUdpResult(Param.Url,
					"ssrf Vulnerable",
					[]string{string(req1.String())},
					[]string{string(r1)},
					"middle",
					Param.Hostid)
				return Result, true, errs
			}
		}
		return nil, false, errors.New("params errors")
	} else {
		for _, uri := range payloads {
			req1, resp1, errs := sess.Get(uri, Param.Headers)
			if errs != nil {
				return nil, false, errs
			}
			r1 := resp1.Body()
			if reverse2.ReverseCheck(reverse, 5) {
				Result := util.VulnerableTcpOrUdpResult(Param.Url,
					"ssrf Vulnerable",
					[]string{string(req1.String())},
					[]string{string(r1)},
					"middle",
					Param.Hostid)
				return Result, true, errs
			}
		}
	}

	return nil, false, errors.New("params errors")
}
