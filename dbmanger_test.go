package main

import (
	"glint/dbmanager"
	"testing"
)

func Test_GetConfig(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}
	v, err := Dm.GetTaskConfig(1)
	if err != nil {
		t.Error(err)
	}
	Dm.ConvertDbTaskConfigToJson(v)
}

func Test_InstallScanResult(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}
	err = Dm.ReplaceVulnerable(
		1,
		"xss",
		true,
		"http://rongji.com",
		"desad",
		"sdas",
		"dasda",
		"high",
	)
	if err != nil {
		t.Error(err)
	}
}
