package main

import (
	"fmt"
	"testing"
	cel "wenscan/cel"

	color "github.com/logrusorgru/aurora"
)

func Test_xray_payload(t *testing.T) {
	c := cel.InitCelOptions()
	_, err := cel.InitCelEnv(&c)
	if err != nil {
		fmt.Println(color.Sprintf("environment creation error: %s\n", color.Red(err)))
	}
}
