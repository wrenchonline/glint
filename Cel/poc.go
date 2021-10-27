package cel

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
	"wenscan/utils"

	"github.com/thoas/go-funk"
	"gopkg.in/yaml.v2"
)

type Poc struct {
	Name   string            `yaml:"name"`
	Set    map[string]string `yaml:"set"`
	Rules  []Rules           `yaml:"rules"`
	Detail Detail            `yaml:"detail"`
}

type Rules struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	Search          string            `yaml:"search"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Expression      string            `yaml:"expression"`
}

type Detail struct {
	Author      string   `yaml:"author"`
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
}

func LoadSinglePoc(fileName string) (*Poc, error) {
	return loadPoc(fileName)
}

func LoadMultiPoc(fileName string) []*Poc {
	fileName = strings.ReplaceAll(fileName, "\\", "/")
	var pocs []*Poc
	for _, f := range selectPoc(fileName) {
		if p, err := loadPoc(f); err == nil {
			pocs = append(pocs, p)
		}
	}
	return pocs
}

func loadPoc(fileName string) (*Poc, error) {
	p := &Poc{}
	yamlFile, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		return nil, err
	}
	return p, err
}

func selectPoc(fileName string) []string {
	return funk.UniqString(singlePoc(fileName))
}

func singlePoc(fileName string) []string {
	var foundFiles []string
	if strings.HasSuffix(fileName, ".yml") || strings.HasSuffix(fileName, ".yaml") {
		if utils.FileExists(fileName) {
			foundFiles = append(foundFiles, fileName)
		}
	}
	// get more poc
	if strings.Contains(fileName, "*") && strings.Contains(fileName, "/") {
		asbPath, _ := filepath.Abs(fileName)
		baseSelect := filepath.Base(fileName)
		files := utils.GetFileNames(filepath.Dir(asbPath), "yml")
		//fmt.Println(files, baseSelect, asbPath)
		for _, f := range files {
			baseFile := filepath.Base(f)
			//if len(baseFile) == 1 && baseFile == "*" {
			if len(baseSelect) == 1 && baseSelect == "*" { //baseSelect为*则全部加入
				foundFiles = append(foundFiles, f)
				continue
			}
			if r, err := regexp.Compile(baseSelect); err != nil { //不符合正则表达式，如单个*，或者具体文件名
				fmt.Println(f, baseSelect)
				if strings.Contains(f, baseSelect) {
					foundFiles = append(foundFiles, f)
				}
			} else { //符合正则表达式，如.*
				if r.MatchString(baseFile) {
					foundFiles = append(foundFiles, f)
				}
			}
		}
	}
	return foundFiles
}
