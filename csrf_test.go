package main

import (
	"testing"
	"wenscan/config"
	"wenscan/csrf"
)

func Test_Name(t *testing.T) {
	data := make(map[string][]interface{})
	config.ReadConf("result.json", &data)
	config.HandleConf(&data, csrf.Origin)

}
