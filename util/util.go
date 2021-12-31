package util

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"glint/logger"
	"io"
	"os"

	// conf2 "github.com/jweny/pocassist/pkg/conf"
	// log "github.com/jweny/pocassist/pkg/logging"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

func Setup() {
	// 请求限速 limiter 初始化
	InitRate()
	// fasthttp client 初始化
	DownProxy := "127.0.0.1:7777"
	client := &fasthttp.Client{
		// If InsecureSkipVerify is true, TLS accepts any certificate
		TLSConfig:                &tls.Config{InsecureSkipVerify: true},
		NoDefaultUserAgentHeader: true,
		DisablePathNormalizing:   true,
	}
	if DownProxy != "" {
		logger.Info("[fasthttp client use proxy ]", DownProxy)
		client.Dial = fasthttpproxy.FasthttpHTTPDialer(DownProxy)
	}

	fasthttpClient = client

	// jwt secret 初始化
	// jwtSecret = []byte("test")
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

func MergeMap(mObj ...map[int]interface{}) map[int]interface{} {
	newObj := map[int]interface{}{}
	for _, m := range mObj {
		for k, v := range m {
			newObj[k] = v
		}
	}
	return newObj
}

func StrMd5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func ConvertHeaders(h map[string]interface{}) map[string]string {
	a := map[string]string{}
	for key, value := range h {
		if value != nil {
			a[key] = value.(string)
		}
	}
	return a
}

func ReadFile(filePath string) []string {
	filePaths := []string{}
	f, err := os.OpenFile(filePath, os.O_RDONLY, 0644)
	defer f.Close()
	if err != nil {
		fmt.Println(err.Error())
	} else {
		rd := bufio.NewReader(f)
		for {
			line, err := rd.ReadString('\n')
			if err != nil || io.EOF == err {
				break
			}
			filePaths = append(filePaths, line)
		}
	}
	return filePaths
}

func JsontoStr(Element interface{}) (string, error) {
	jsonElement, err := json.Marshal(Element)
	if err != nil {
		logger.Error(err.Error())
	}
	msgstr := string(jsonElement)
	return msgstr, err
}

func CopyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range m {
		vm, ok := v.(map[string]interface{})
		if ok {
			cp[k] = CopyMap(vm)
		} else {
			cp[k] = v
		}
	}

	return cp
}
