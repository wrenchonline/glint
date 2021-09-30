package main

import (
	"net/url"
	"testing"
	cf "wenscan/config"
	http "wenscan/http"
	sql "wenscan/sql"
)

func TestSqlerror(t *testing.T) {
	Spider := http.Spider{}
	Spider.Init()
	defer Spider.Close()
	c := cf.Conf{}
	//读取配置文件
	conf := c.GetConf()
	Spider.ReqMode = conf.ReqMode
	if err := Spider.SetCookie(conf); err != nil {
		panic(err)
	}
	Spider.Url, _ = url.Parse("http://localhost/vulnerabilities/sqli/?id=dsad&Submit=Submit#")
	sql.Validationsqlerror(&Spider)
}
