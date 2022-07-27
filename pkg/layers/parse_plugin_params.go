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

func (p *PluginParam) ParsePluginParams(group plugin.GroupData) {
	session := group.GroupUrls.(map[string]interface{})
	p.Url = session["url"].(string)
	p.Method = session["method"].(string)
	p.Headers, _ = util.ConvertHeaders(session["headers"].(map[string]interface{}))
	p.Body = session["data"].(string)
	p.TaskConfig = group.Config
	p.Cert = group.HttpsCert
	p.CertKey = group.HttpsCertKey
	p.Timeout, _ = group.Config.Json.Exweb_scan_param.Http_response_timeout.Int64()
	if value, ok := session["hostid"].(int64); ok {
		p.Hostid = value
	}

	if value, ok := session["hostid"].(json.Number); ok {
		p.Hostid, _ = value.Int64()
	}
	p.Ctx = group.Pctx
	p.UpProxy = group.Config.Json.Exweb_scan_param.Http_proxy

	if value, ok := p.Headers["Content-Type"]; ok {
		p.ContentType = value
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
