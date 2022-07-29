package layers

import (
	"context"
	"encoding/json"
	"glint/config"
	"glint/plugin"
	"glint/util"
)

type PluginParam struct {
	Ctx         *context.Context
	Url         string
	Method      string
	Headers     map[string]string
	Body        string
	TaskConfig  *config.TaskConfig
	Cert        string
	CertKey     string
	Timeout     int64
	Hostid      int64
	UpProxy     string
	ContentType string
}

type CheckType struct {
	Urlindex       int  //传递url的位置
	IsMultipleUrls bool //是否一次检测多个url
}

func (p *PluginParam) ParsePluginParams(group plugin.GroupData, ct CheckType) {
	Session := make(map[string]interface{})
	if !ct.IsMultipleUrls {
		Session = group.Url
	} else {
		Session = group.GroupUrls[ct.Urlindex].(map[string]interface{})
	}
	p.Url = Session["url"].(string)
	p.Method = Session["method"].(string)
	p.Headers, _ = util.ConvertHeaders(Session["headers"].(map[string]interface{}))
	p.Body = Session["data"].(string)

	if value, ok := Session["hostid"].(int64); ok {
		p.Hostid = value
	}

	if value, ok := Session["hostid"].(json.Number); ok {
		p.Hostid, _ = value.Int64()
	}

	if value, ok := p.Headers["Content-Type"]; ok {
		p.ContentType = value
	}

	p.Ctx = group.Pctx
	p.TaskConfig = group.Config
	p.Cert = group.HttpsCert
	p.CertKey = group.HttpsCertKey
	if group.Config != nil {
		p.UpProxy = group.Config.Json.Exweb_scan_param.Http_proxy
		p.Timeout, _ = group.Config.Json.Exweb_scan_param.Http_response_timeout.Int64()
	} else {
		p.UpProxy = ""
		p.Timeout = 5
	}

}

func (p *PluginParam) CheckForExitSignal() bool {
	select {
	case <-(*p.Ctx).Done():
		return true
	default:
	}
	return false
}
