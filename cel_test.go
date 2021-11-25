package main

import (
	"fmt"
	cel "glint/cel"
	"glint/util"
	"net/http"
	"testing"

	color "github.com/logrusorgru/aurora"
)

func Test_xray_payload(t *testing.T) {
	util.Setup()
	poc, err := cel.LoadPoc("../xray-pocs/apache-httpd-cve-2021-41773-path-traversal.yml", "Yaml")
	if err != nil {
		fmt.Println(color.Sprintf("[Test_xray_payload] LoadPoc  error: %s\n", color.Red(err)))
	}
	Plugin := &cel.Plugin{VulId: "0", Affects: "directory", JsonPoc: poc, Enable: true}
	httpreq, err := http.NewRequest("Get", "http://192.168.166.192/", nil)
	if err != nil {
		fmt.Println(color.Sprintf("[Test_xray_payload] NewRequest error: %s\n", color.Red(err)))
	}
	ScanItem := cel.ScanItem{OriginalReq: httpreq, Plugin: Plugin}
	result, err := cel.RunPoc(&ScanItem, true)
	if err != nil {
		fmt.Println(color.Sprintf("[Test_xray_payload] RunPoc error: %s\n", color.Red(err)))
	}
	fmt.Println(*result)
}
