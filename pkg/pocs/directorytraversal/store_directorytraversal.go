package directorytraversal

import (
	"encoding/json"
	"glint/fastreq"
	"glint/plugin"
	"glint/util"
	"time"
)

var DefaultProxy = ""
var Cert string
var Mkey string

func TraversalVaild(args interface{}) (*util.ScanResult, bool, error) {
	var err error
	var variations *util.Variations
	var ContentType string
	var DirectoryTraversal classDirectoryTraversal
	var hostid int64
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
	body := []byte(session["data"].(string))
	Cert = group.HttpsCert
	Mkey = group.HttpsCertKey
	sess := fastreq.GetSessionByOptions(
		&fastreq.ReqOptions{
			Timeout:       10 * time.Second,
			AllowRedirect: true,
			Proxy:         DefaultProxy,
			Cert:          Cert,
			PrivateKey:    Mkey,
		})

	if value, ok := session["hostid"].(int64); ok {
		hostid = value
	}

	if value, ok := session["hostid"].(json.Number); ok {
		hostid, _ = value.Int64()
	}

	// variations,err = util.ParseUri(url)
	// BlindSQL.variations =
	if value, ok := headers["Content-Type"]; ok {
		ContentType = value
	}
	variations, err = util.ParseUri(url, body, method, ContentType)
	//赋值
	DirectoryTraversal.variations = variations
	DirectoryTraversal.lastJob.Layer.Sess = sess
	DirectoryTraversal.TargetUrl = url
	DirectoryTraversal.lastJob.Layer.Method = method
	DirectoryTraversal.lastJob.Layer.ContentType = ContentType
	DirectoryTraversal.lastJob.Layer.Headers = headers
	DirectoryTraversal.lastJob.Layer.Body = body

	if DirectoryTraversal.startTesting() {
		// println(hostid)
		// println("发现sql漏洞")
		//....................
		Result := util.VulnerableTcpOrUdpResult(url,
			"DirectoryTraversal Vulnerable",
			[]string{string(DirectoryTraversal.lastJob.Features.Request.String())},
			[]string{string(DirectoryTraversal.lastJob.Features.Response.String())},
			"high",
			hostid)
		return Result, true, err
	}
	return nil, false, err
}
