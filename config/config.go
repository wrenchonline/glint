package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/thoas/go-funk"
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
