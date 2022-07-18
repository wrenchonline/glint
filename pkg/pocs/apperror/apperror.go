package apperror

import (
	"bytes"
	"encoding/json"
	"fmt"
	"glint/fastreq"
	"glint/logger"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/thoas/go-funk"
)

//这个就在主要插件中调用回调会好点。
func Test_Application_error(body string) (bool, string) {
	//var MatchString string
	for _, plain := range layers.ErrorMessagesPlainText {
		if funk.Contains(body, plain) {
			return true, plain
		}
	}
	for _, regex := range layers.ErrorMessagesRegexes {
		r, _ := regexp.Compile(regex)
		C := r.FindAllStringSubmatch(body, -1)
		if len(C) != 0 {
			return true, C[0][0]
		}
	}
	return false, ""
}

var DefaultProxy = ""
var cert string
var mkey string

type ErrorVulnDetail struct {
	Url         string `json:"url"`
	MatchString string `json:"matchString"`
}

type ErrorVulnDetails struct {
	VulnerableList []ErrorVulnDetail
}

func (e *ErrorVulnDetails) String() string {
	var buf bytes.Buffer
	for _, v := range e.VulnerableList {
		buf.WriteString(fmt.Sprintf("Url:%s\n", v.Url))
		buf.WriteString(fmt.Sprintf("%s\n", v.MatchString))
	}
	return buf.String()
}

var threadwg sync.WaitGroup //同步线程

func Application_startTest(args interface{}) (*util.ScanResult, bool, error) {
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
	var VulnList = ErrorVulnDetails{}
	var err error
	if sessions, ok := group.GroupUrls.([]interface{}); ok {
		threadwg.Add(len(sessions))
		go func() {
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
						Timeout:       2 * time.Second,
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
				}
				if isVuln, matchstr := Test_Application_error(resp.String()); isVuln {
					IsVuln = true
					if VulnURl == "" {
						VulnURl = url
					}
					VulnInfo := ErrorVulnDetail{Url: url, MatchString: matchstr}
					VulnList.VulnerableList = append(VulnList.VulnerableList, VulnInfo)
				}
				threadwg.Done()
			}
		}()
		threadwg.Wait()
	}
	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(VulnURl,
			VulnList.String(),
			[]string{""},
			[]string{""},
			"middle",
			hostid)
		return Result, true, err
	}
	return nil, false, err
}
