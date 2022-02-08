package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
)

var Lens int = 4

func Test_binary(t *testing.T) {

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
