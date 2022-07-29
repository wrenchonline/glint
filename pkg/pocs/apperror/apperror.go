package apperror

import (
	"bytes"
	"fmt"
	"glint/logger"
	"glint/nenet"
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

	IsVuln := false
	var hostid int64
	var VulnURl = ""
	var VulnList = ErrorVulnDetails{}
	var err error
	// if sessions, ok := group.GroupUrls; ok {
	threadwg.Add(len(group.GroupUrls))
	go func() {
		for idx, _ := range group.GroupUrls {

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
			}
			if isVuln, matchstr := Test_Application_error(resp.String()); isVuln {
				IsVuln = true
				if VulnURl == "" {
					VulnURl = Param.Url
				}
				VulnInfo := ErrorVulnDetail{Url: Param.Url, MatchString: matchstr}
				VulnList.VulnerableList = append(VulnList.VulnerableList, VulnInfo)
			}
			threadwg.Done()
		}
	}()
	threadwg.Wait()
	//}
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
