package cspnotimplement

import (
	"bytes"
	"fmt"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"strings"
	"sync"
	"time"

	"github.com/thoas/go-funk"
)

var DefaultProxy = ""
var cert string
var mkey string

type CSPVulnDetail struct {
	Url string `json:"url"`
}

type CSPVulnDetails struct {
	VulnerableList []CSPVulnDetail
}

func (e *CSPVulnDetails) String() string {
	var buf bytes.Buffer
	for _, v := range e.VulnerableList {
		buf.WriteString(fmt.Sprintf("Url:%s\n", v.Url))
	}
	return buf.String()
}

//crlfCheck
var payload_template = []string{
	`Content-Security-Policy:`,
	`Content-Security-Policy-Report-Only:`,
}

var threadwg sync.WaitGroup //同步线程

func CSPStartTest(args interface{}) (*util.ScanResult, bool, error) {
	util.Setup()
	group := args.(plugin.GroupData)
	// ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	ctx := *group.Pctx

	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	default:
	}
	IsVuln := false

	var VulnURl = ""
	var VulnList = CSPVulnDetails{}
	var err error

	threadwg.Add(len(group.GroupUrls))
	go func() {
		for idx, _ := range group.GroupUrls {
			defer threadwg.Done()
			var Param layers.PluginParam
			ct := layers.CheckType{IsMultipleUrls: true, Urlindex: idx}
			Param.ParsePluginParams(args.(plugin.GroupData), ct)
			if Param.CheckForExitSignal() {
				return
			}
			sess := nenet.GetSessionByOptions(
				&nenet.ReqOptions{
					Timeout:       time.Duration(Param.Timeout) * time.Second,
					AllowRedirect: false,
					Proxy:         Param.UpProxy,
					Cert:          Param.Cert,
					PrivateKey:    Param.CertKey,
				})
			_, resp, err := sess.Request(strings.ToUpper(Param.Method), Param.Url, Param.Headers, []byte(Param.Body))
			if err != nil {
				logger.Debug("%s", err.Error())
				return
			}

			Text := string(resp.Header.Header())
			logger.Debug("csp vuln headers:\n %v", Text)
			for _, v := range payload_template {
				if !funk.Contains(strings.ToLower(Text), strings.ToLower(v)) {
					IsVuln = true
					if VulnURl == "" {
						VulnURl = Param.Url
					}
					VulnInfo := CSPVulnDetail{Url: Param.Url}
					VulnList.VulnerableList = append(VulnList.VulnerableList, VulnInfo)
				}
			}

		}
	}()
	threadwg.Wait()
	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(VulnURl,
			VulnList.String(),
			[]string{""},
			[]string{""},
			"information",
			65535)
		return Result, true, err
	}
	return nil, false, err
}
