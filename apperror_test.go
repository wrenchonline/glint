package main

import (
	"fmt"
	"regexp"
	"testing"
)

func Test_regex(t *testing.T) {
	regexstr := `(?i)(SQL[\s\S]error[\s\S]*)`
	r, _ := regexp.Compile(regexstr)
	C := r.FindAllStringSubmatch("SQL ERROR: syntax error at or near", -1)
	if len(C) != 0 {
		fmt.Println("sinks match")
	}
}
