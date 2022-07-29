package directorytraversal

import (
	"errors"
	"glint/nenet"
	"glint/pkg/layers"
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
	//var hostid int64
	// var blastIters interface{}
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

	// variations,err = util.ParseUri(url)
	// BlindSQL.variations =
	if value, ok := Param.Headers["Content-Type"]; ok {
		ContentType = value
	}
	variations, err = util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, ContentType)
	//赋值
	DirectoryTraversal.variations = variations
	DirectoryTraversal.lastJob.Layer.Sess = sess
	DirectoryTraversal.TargetUrl = Param.Url
	DirectoryTraversal.lastJob.Layer.Method = Param.Method
	DirectoryTraversal.lastJob.Layer.ContentType = ContentType
	DirectoryTraversal.lastJob.Layer.Headers = Param.Headers
	DirectoryTraversal.lastJob.Layer.Body = []byte(Param.Body)

	if DirectoryTraversal.startTesting() {
		// println(hostid)
		// println("发现sql漏洞")
		//....................
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"DirectoryTraversal Vulnerable",
			[]string{string(DirectoryTraversal.lastJob.Features.Request.String())},
			[]string{string(DirectoryTraversal.lastJob.Features.Response.String())},
			"high",
			Param.Hostid)
		return Result, true, err
	}
	return nil, false, err
}
