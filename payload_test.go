package main

import (
	"fmt"
	"testing"
	payload "wenscan/payload"
)

func Test_Payload(t *testing.T) {
	payloads, err := payload.LoadPayloadData("./xss.yaml")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(payloads)
}
