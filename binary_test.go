package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

var Lens int = 4

func Test_binary(t *testing.T) {
	var r *http.Request
	r.ParseForm()
	reponse := make(map[string]interface{})
	reponse["status"] = "0"
	reponse["msg"] = "dsadsa"
	reponse["taskid"] = strconv.Itoa(4)
	data, err := json.Marshal(reponse)
	if err != nil {
		t.Error(err)
	}

	bs := make([]byte, len(data)+4)
	binary.BigEndian.PutUint32(bs, uint32(len(data)+4))
	copy(bs[4:], data)

	fmt.Printf("%x \n", bs[:4])

	response := make(map[string]interface{})
	err = json.Unmarshal(bs[4:], &response)
	if err != nil {
		t.Error(err)
	}
}

func Test_jsoncompost(t *testing.T) {
	jsonobj := make(map[string]interface{})
	jsonobj["test"] = "dsa"
	jsonobj["test2"] = "jsonfg"
	var payloads []string

	newjsonobj := make(map[string]interface{})

	payload := "555"

	for k, v := range jsonobj {
		newjsonobj[k] = v
	}

	for k, v := range newjsonobj {
		newjsonobj[k] = payload
		binary, _ := json.Marshal(newjsonobj)
		payloads = append(payloads, string(binary))
		newjsonobj[k] = v
	}
	fmt.Println(payloads)
}
