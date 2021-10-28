package util

import (
	"crypto/tls"
	"os"
	log "wenscan/Log"

	// conf2 "github.com/jweny/pocassist/pkg/conf"
	// log "github.com/jweny/pocassist/pkg/logging"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

func Setup() {
	// 请求限速 limiter 初始化
	InitRate()
	// fasthttp client 初始化
	DownProxy := ""
	client := &fasthttp.Client{
		// If InsecureSkipVerify is true, TLS accepts any certificate
		TLSConfig:                &tls.Config{InsecureSkipVerify: true},
		NoDefaultUserAgentHeader: true,
		DisablePathNormalizing:   true,
	}
	if DownProxy != "" {
		log.Info("[fasthttp client use proxy ]", DownProxy)
		client.Dial = fasthttpproxy.FasthttpHTTPDialer(DownProxy)
	}

	fasthttpClient = client

	// jwt secret 初始化
	jwtSecret = []byte("test")
}

func IsFileExist(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}
