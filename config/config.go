package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"wenscan/util"

	"github.com/thoas/go-funk"
	"github.com/valyala/fasthttp"
	"gopkg.in/yaml.v2"
)

type Conf struct {
	Crawler   Crawler                `yaml:"crawler"`
	SqlInject SqlInject              `yaml:"sqlinject"`
	Url       string                 `yaml:"url"`
	Xss       Xss                    `yaml:"xss"`
	ReqMode   string                 `yaml:"reqmode"`
	Headers   map[string]interface{} `yaml:"headers"`
}

type SqlInject struct {
	Attacktype     string   `yaml:"attacktype"`
	Attackpayloads []string `yaml:"attackpayloads"`
}

type Xss struct {
	Xsspayload []string `yaml:"xsspayload"`
}

type Crawler struct {
	Url       []string `yaml:"url"`
	Brokenurl []string `yaml:"brokenurl"`
}

func (conf *Conf) GetConf() *Conf {
	yamlFile, err := ioutil.ReadFile("conf.yaml")
	if err != nil {
		fmt.Println(err.Error())
	}
	err = yaml.Unmarshal(yamlFile, conf)
	if err != nil {
		fmt.Println(err.Error())
	}
	return conf
}

func ReadConf(file string, data *map[string][]interface{}) error {
	jsonFile, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	// FileJsonUrls := make(map[string]interface{})
	err = json.Unmarshal([]byte(byteValue), data)
	if err != nil {
		fmt.Println(err)
	}
	return err
}

type CrawCallback func(k string, v []interface{}) error

func HandleConf(data map[string][]interface{}, callback CrawCallback) interface{} {
	errlist := funk.Map(data, func(k string, v []interface{}) error {
		err := callback(k, v)
		return err
	})
	return errlist
}

func CopyConfReq(data interface{}, dstRequest *fasthttp.Request) error {
	req := http.Request{}
	var (
		err  error
		Data []byte
	)
	switch json := data.(type) {
	case map[string]interface{}:
		req.Method = json["method"].(string)
		req.URL, _ = url.Parse(json["url"].(string))
		postform := url.Values{}
		postvalues := strings.Split(json["data"].(string), "&")
		for _, value := range postvalues {
			k := strings.Split(value, "=")[0]
			v := strings.Split(value, "=")[1]
			postform[k] = []string{v}
		}
		req.PostForm = postform
		for k, v := range json["headers"].(map[string]interface{}) {
			req.Header.Set(k, v.(string))
		}
		Data, err = util.GetOriginalReqBody(&req)
		util.CopyRequest(&req, dstRequest, Data)
	}
	return err
}
