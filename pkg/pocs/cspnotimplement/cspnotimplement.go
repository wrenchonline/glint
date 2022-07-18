package cspnotimplement

import (
	"bytes"
	"encoding/json"
	"fmt"
	"glint/fastreq"
	"glint/logger"
	"glint/plugin"
	"glint/util"
	"strings"
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
	var hostid int64
	var VulnURl = ""
	var VulnList = CSPVulnDetails{}
	var err error
	if sessions, ok := group.GroupUrls.([]interface{}); ok {
		for _, session := range sessions {
			newsess := session.(map[string]interface{})
			url := newsess["url"].(string)
			method := newsess["method"].(string)
			headers, _ := util.ConvertHeaders(newsess["headers"].(map[string]interface{}))
			body := []byte(newsess["data"].(string))
			cert = group.HttpsCert
			mkey = group.HttpsCertKey
			sess := fastreq.GetSessionByOptions(
				&fastreq.ReqOptions{
					Timeout:       3 * time.Second,
					AllowRedirect: true,
					Proxy:         DefaultProxy,
					Cert:          cert,
					PrivateKey:    mkey,
				})

			if hostid == 0 {
				if value, ok := newsess["hostid"].(int64); ok {
					hostid = value
				}
				if value, ok := newsess["hostid"].(json.Number); ok {
					hostid, _ = value.Int64()
				}
			}
			_, resp, err := sess.Request(strings.ToUpper(method), url, headers, body)
			if err != nil {
				logger.Debug("%s", err.Error())
				return nil, false, err
			}

			Text := string(resp.Header.Header())
			logger.Debug("csp vuln headers:\n %v", Text)
			for _, v := range payload_template {
				if !funk.Contains(strings.ToLower(Text), strings.ToLower(v)) {
					IsVuln = true
					if VulnURl == "" {
						VulnURl = url
					}
					VulnInfo := CSPVulnDetail{Url: url}
					VulnList.VulnerableList = append(VulnList.VulnerableList, VulnInfo)
				}
			}
		}
	}
	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(VulnURl,
			VulnList.String(),
			[]string{""},
			[]string{""},
			"information",
			hostid)
		return Result, true, err
	}
	return nil, false, err
}
