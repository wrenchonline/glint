package main

import (
	"glint/config"
	"glint/pkg/layers"
	"glint/util"
	"testing"
)

func Test_layers(t *testing.T) {
	// var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("result_1.json")
	// for _, v := range data {
	// 	d := v.([]interface{})

	// }
	headers, _ := util.ConvertHeaders(data["headers"])
	pl := layers.Plreq{}
	pl.Method = data["method"].(string)
	pl.Body = []byte(data["data"].(string))
	pl.Headers = headers
	pl.ContentType = headers["Content-Type"]
	pl.Init("", "server.pem", "server.key")
	Features1, _ := pl.RequestAll(data["url"].(string), "dsasd")
	// pl.Method = "GET"
	Features2, _ := pl.RequestAll(data["url"].(string), "2112")
	if !layers.CompareFeatures(&Features1, &Features2) {
		println("false")
	} else {
		println("true")
	}

}
