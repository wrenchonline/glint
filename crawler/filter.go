package crawler

import "github.com/thoas/go-funk"

var ForbidenKey = []string{
	"css",
	"js",
	"ico",
	"woff2",
	"woff",
}

//FilterKey 过滤关键url
func FilterKey(url string, forbiden []string) bool {
	for _, v := range forbiden {
		if funk.Contains(url, v) {
			return true
		}
	}
	return false
}
