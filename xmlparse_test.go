package main

import (
	"glint/util"
	"testing"
)

func Test_XMl(t *testing.T) {
	xml := `<user><username>dsada</username><password>dsadsa</password></user>`
	util.ParseXMl([]byte(xml))
}
