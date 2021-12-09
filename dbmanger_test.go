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
