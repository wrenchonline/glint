package cel

import (
	"fmt"
	"glint/logger"
	"glint/proto"
	"glint/reverse"
	"glint/util"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v2"
)

type Poc struct {
	Params []string          `json:"params"`
	Name   string            `json:"name"`
	Set    yaml.MapSlice     `json:"set"`
	Rules  []Rule            `json:"rules"`
	Groups map[string][]Rule `json:"groups"`
	Detail Detail            `json:"detail"`
}

type Rule struct {
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	Search          string            `json:"search"`
	FollowRedirects bool              `json:"follow_redirects"`
	Expression      string            `json:"expression"`
}

type Detail struct {
	Author      string   `json:"author"`
	Links       []string `json:"links"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
}

type CelController struct {
	Env      *cel.Env               // cel env
	ParamMap map[string]interface{} // 注入到cel中的变量
}

type Plugin struct {
	VulId   string // 漏洞编号
	Affects string // 影响类型  dir/server/param/url/content
	JsonPoc *Poc   // json规则
	Enable  bool   // 是否启用
}

//	初始化
func (cc *CelController) Init(poc *Poc) (err error) {
	//	1.生成cel env环境
	option := InitCelOptions()
	//	注入set定义的变量
	if poc.Set != nil {
		option.AddRuleSetOptions(poc.Set)
	}
	env, err := InitCelEnv(&option)
	if err != nil {
		logger.Error("[cel/cel.go:Init init cel env error]", err)
		return err
	}
	cc.Env = env
	// 初始化变量列表
	cc.ParamMap = make(map[string]interface{})
	return nil
}

// 处理poc: set
func (cc *CelController) InitSet(poc *Poc, newReq *proto.Request) (err error) {
	// 如果没有set 就直接返回
	if len(poc.Set) == 0 {
		return
	}
	cc.ParamMap["request"] = newReq

	for _, setItem := range poc.Set {
		key := setItem.Key.(string)
		value := setItem.Value.(string)
		// 反连平台
		if value == "newReverse()" {
			cc.ParamMap[key] = reverse.NewReverse()
			continue
		}
		out, err := Evaluate(cc.Env, value, cc.ParamMap)
		if err != nil {
			return err
		}
		switch value := out.Value().(type) {
		// set value 无论是什么类型都先转成string
		case *proto.UrlType:
			cc.ParamMap[key] = util.UrlTypeToString(value)
		case int64:
			cc.ParamMap[key] = int(value)
		default:
			cc.ParamMap[key] = fmt.Sprintf("%v", out)
		}
	}
	return
}

// 计算cel表达式
func (cc *CelController) Evaluate(char string) (bool, error) {
	out, err := Evaluate(cc.Env, char, cc.ParamMap)
	if err != nil {
		logger.Error("[cel/cel.go:Evaluate error]", err)
		return false, err
	}
	if fmt.Sprintf("%v", out) == "false" {
		return false, nil
	}
	return true, nil
}

func (cc *CelController) Reset() {
	cc.Env = nil
	cc.ParamMap = nil
}
