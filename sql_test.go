package main

import "testing"

func Test_sql_math(t *testing.T) {
	x := 5 % 18
	println(x)
	var origValue = "swqedq"
	paramValue := origValue[:1] + "'||'" + origValue[1:]
	println(paramValue)
}
