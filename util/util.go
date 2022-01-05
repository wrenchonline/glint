package util

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"glint/logger"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

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

type post struct {
	Key   string
	Value string
	index int //
	// url   string
}

type Param []post

//Len()
func (s Param) Len() int {
	return len(s)
}

//Less(): 顺序有低到高排序
func (s Param) Less(i, j int) bool {
	return s[i].index < s[j].index
}

//Swap()
func (s Param) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s *Param) Release() string {
	var buf bytes.Buffer
	for i, post := range *s {
		buf.WriteString(post.Key + "=" + post.Value)
		if i != s.Len()-1 {
			buf.WriteString("&")
		}
	}
	return buf.String()
}

func (s Param) Set(key string, value string) error {
	for i, p := range s {
		if p.Key == key {
			s[i].Value = value
			return nil
		}
	}
	return fmt.Errorf("not found: %s", key)
}

func (s *Param) SetPayload(uri string, payload string, method string) []string {
	var result []string
	if strings.ToUpper(method) == "POST" {
		for _, kv := range *s {
			s.Set(kv.Key, payload)
			result = append(result, s.Release())
			s.Set(kv.Key, kv.Value)
		}
	} else if strings.ToUpper(method) == "GET" {
		u, err := url.Parse(uri)
		if err != nil {
			logger.Error(err.Error())
			return nil
		}
		v := u.Query()
		for _, kv := range *s {
			v.Set(kv.Key, payload)
			result = append(result, strings.Split(string(uri), "?")[0]+"?"+v.Encode())
			v.Set(kv.Key, kv.Value)
		}
	}
	return result
}

func ParseUri(uri string, body []byte, method string) (Param, error) {
	var err error
	if strings.ToUpper(method) == "POST" {
		if len(body) > 0 {
			strs := strings.Split(string(body), "&")
			params := Param{}
			for i, kv := range strs {
				key := strings.Split(string(kv), "=")[0]
				value := strings.Split(string(kv), "=")[1]
				Post := post{Key: key, Value: value, index: i}
				params = append(params, Post)
			}
			sort.Sort(params)
			return params, nil
		} else {
			return nil, fmt.Errorf("post data is empty")
		}

	} else if strings.ToUpper(method) == "GET" {
		urlparams := strings.Split(string(uri), "?")[1]
		strs := strings.Split(string(urlparams), "&")
		params := Param{}
		for i, kv := range strs {
			key := strings.Split(string(kv), "=")[0]
			value := strings.Split(string(kv), "=")[1]
			Post := post{Key: key, Value: value, index: i}
			params = append(params, Post)
		}
		sort.Sort(params)
		return params, nil
	} else {
		err = fmt.Errorf("method not supported")
	}
	return nil, err
}
