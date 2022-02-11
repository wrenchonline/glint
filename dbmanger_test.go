package main

import (
	"encoding/base64"
	"glint/dbmanager"
	"glint/util"
	"testing"
	"time"
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
	err = Dm.SaveScanResult(
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

func Test_install_http_status_(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}
	State := dbmanager.PublishState{
		Id:          dbmanager.NewNullString("id"),
		Host:        dbmanager.NewNullString("Host"),
		Method:      dbmanager.NewNullString("Method"),
		Data:        dbmanager.NewNullString(base64.RawStdEncoding.EncodeToString([]byte{})),
		UserAgent:   dbmanager.NewNullString("UserAgent"),
		ContentType: dbmanager.NewNullString("ContentType"),
		CreatedTime: time.Now().Local(),
	}
	err = Dm.InstallHttpsReqStatus(&State)
	if err != nil {
		t.Error(err)
	}
}

func Test_QuitTime(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}
	start_scan := time.Now()
	time.Sleep(1 * time.Second)
	over_time := util.FmtDuration(time.Since(start_scan))
	err = Dm.SaveQuitTime(
		1,
		start_scan,
		over_time,
	)
	if err != nil {
		t.Error(err)
	}
}
