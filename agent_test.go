package main

import (
	"testing"
)

func Test_SProxy(t *testing.T) {
	// var req *http.Request
	// cookies := req.Cookies()

	// for _, cookie := range cookies {
	// 	cookie.String()
	// }
	s := SProxy{}
	s.Run()
}
