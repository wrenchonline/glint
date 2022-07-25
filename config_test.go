package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"glint/config"
	"io/ioutil"
	"os"
	"testing"
)

func Test_Config(t *testing.T) {
	file := "itop_task.json"
	jsonFile, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	JsonObj := config.TaskJsonConfig{}
	d := json.NewDecoder(bytes.NewReader(byteValue))
	d.UseNumber()
	d.Decode(&JsonObj)
	fmt.Println(JsonObj)
}
