package main

import (
	"glint/config"
	"glint/csrf"
	"testing"
)

func Test_Name(t *testing.T) {
	data := make(map[string][]interface{})
	config.ReadResultConf("result.json", &data)
	config.HandleResult(data, csrf.Origin)
	config.HandleResult(data, csrf.Referer)
}
