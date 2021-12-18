package cel

import (
	"errors"
	"fmt"
	"glint/logger"
	"glint/util"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type ScriptScanArgs struct {
	Host    string
	Port    uint16
	IsHTTPS bool
}

type ScriptScanFunc func(args *ScriptScanArgs) (*util.ScanResult, error)

var scriptHandlers = map[string]ScriptScanFunc{}

// GetScriptFunc 返回 pocName 对应的方法
func GetScriptFunc(pocName string) ScriptScanFunc {
	if f, ok := scriptHandlers[pocName]; ok {
		return f
	}
	return nil
}

func ScriptRegister(pocName string, handler ScriptScanFunc) {
	if _, ok := scriptHandlers[pocName]; ok {
		logger.Fatal("[script register vulId ]", pocName)
	}
	scriptHandlers[pocName] = handler
}

func ConstructUrl(args *ScriptScanArgs, uri string) string {
	var rawUrl string
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	var scheme string
	if args.IsHTTPS {
		scheme = "https"
	} else {
		scheme = "http"
	}
	if args.Port == 80 || args.Port == 443 {
		rawUrl = fmt.Sprintf("%v://%v%v", scheme, args.Host, uri)
	} else {
		rawUrl = fmt.Sprintf("%v://%v:%v%v", scheme, args.Host, args.Port, uri)
	}
	return rawUrl
}

func ParseJsonPoc(jsonByte []byte) (*Poc, error) {
	poc := &Poc{}
	err := yaml.Unmarshal(jsonByte, poc)
	if poc.Name == "" {
		errMsg := "poc解析失败，poc名称不可为空"
		logger.Fatal("cel/script.go:ParseJsonPoc Err", errMsg)
		return nil, errors.New(errMsg)
	}
	return poc, err
}

func ParseYamlPoc(yamlByte []byte) (*Poc, error) {
	poc := &Poc{}
	err := yaml.Unmarshal(yamlByte, poc)
	if poc.Name == "" {
		errMsg := "poc parse error"
		logger.Fatal("cel/script.go:ParseYamlPoc Err", errMsg)
		return nil, errors.New(errMsg)
	}
	return poc, err
}

func LoadPocContent(path string) ([]byte, error) {
	if util.IsFileExist(path) {
		file, err := os.Open(path)
		if err != nil {
			logger.Fatal("cel/script.go:LoadPoc Err", err)
		}
		defer file.Close()
		content, err := ioutil.ReadAll(file)
		if err != nil {
			logger.Fatal("cel/script.go:LoadPoc Err", err)
		}
		return content, err
	}
	return nil, errors.New("cel/script.go:LoadPoc File not exist")
}

func LoadPoc(path string, loadtype string) (*Poc, error) {
	if loadtype == "Json" {
		content, err := LoadPocContent(path)
		if err != nil {
			return nil, err
		}
		poc, err := ParseJsonPoc(content)
		if err != nil {
			return nil, err
		}
		return poc, nil
	} else if loadtype == "Yaml" {
		content, err := LoadPocContent(path)
		if err != nil {
			return nil, err
		}
		poc, err := ParseYamlPoc(content)
		if err != nil {
			return nil, err
		}
		return poc, nil
	}
	return nil, errors.New("loadtype invalid")
}
