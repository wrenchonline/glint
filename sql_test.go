package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"testing"
	ast "wenscan/ast"
	brohttp "wenscan/brohttp"
	cf "wenscan/config"
	sql "wenscan/sql"
)

func TestSqlerror(t *testing.T) {
	Spider := brohttp.Spider{}
	Spider.Init()
	defer Spider.Close()
	c := cf.Conf{}
	//读取配置文件
	conf := c.GetConf()
	Spider.ReqMode = conf.ReqMode

	// if err := Spider.SetCookie(conf); err != nil {
	// 	panic(err)
	// }
	jsonFile, err := os.Open("result.json")

	// 最好要处理以下错误
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var JsonUrls []ast.JsonUrl

	err = json.Unmarshal([]byte(byteValue), &JsonUrls)
	// 最好要处理以下错误
	if err != nil {
		fmt.Println(err)
	}
	Spider.Url, _ = url.Parse("http://localhost/vulnerabilities/sqli/?id=312&Submit=Submit#")
	result, err := sql.Validationsqlerror(&Spider)
	if err == nil {
		fmt.Println(result)
	}

}
