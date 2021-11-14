package payload

import (
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

type PayloadData struct {
	Xss map[string]interface{} `yaml:"xss"`
}

func LoadPayloadData(file string) (PayloadData, error) {
	var Data PayloadData
	Data.Xss = make(map[string]interface{})
	yamlFile, err := ioutil.ReadFile(file)
	if err != nil {
		return Data, err
	}
	err = yaml.Unmarshal(yamlFile, Data)
	if err != nil {
		return Data, err
	}
	return Data, nil
}
