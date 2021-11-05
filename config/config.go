package config

import (
	"fmt"
	"io/ioutil"

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

// type Cookies struct {
// 	Name     string `yaml:"name"`
// 	Value    string `yaml:"value"`
// 	Domain   string `yaml:"domain"`
// 	Path     string `yaml:"path"`
// 	HttpOnly bool   `yaml:"httpOnly"`
// 	Secure   bool   `yaml:"secure"`
// }

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
