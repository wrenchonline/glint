package main

import (
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/pkg/pocs/sql"
	"glint/plugin"
	"sync"
	"testing"
	"time"
)

func TestSqlBlind(t *testing.T) {
	logger.DebugEnable(true)
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("sql_test.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, sql.Sql_inject_Vaild)
	pluginInternal := plugin.Plugin{
		PluginName:   "SQL",
		PluginId:     plugin.SQL,
		MaxPoolCount: 5,
		Callbacks:    myfunc,
		Timeout:      30 * time.Second,
	}
	pluginInternal.Init()
	PluginWg.Add(1)
	Progress := 0.
	args := plugin.PluginOption{
		PluginWg: &PluginWg,
		Progress: &Progress,
		IsSocket: false,
		Data:     data,
		TaskId:   999,
		// Sendstatus: &PliuginsMsg,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}

func TestSqlBlindError(t *testing.T) {
	logger.DebugEnable(true)
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_file/sql_error.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, sql.Sql_inject_Vaild)
	pluginInternal := plugin.Plugin{
		PluginName:   "SQL",
		PluginId:     plugin.SQL,
		MaxPoolCount: 5,
		Callbacks:    myfunc,
		Timeout:      999 * time.Second,
	}
	pluginInternal.Init()
	PluginWg.Add(1)
	Progress := 0.
	args := plugin.PluginOption{
		PluginWg: &PluginWg,
		Progress: &Progress,
		IsSocket: false,
		Data:     data,
		TaskId:   999,
		// Sendstatus: &PliuginsMsg,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}

func Test_sql_math(t *testing.T) {
	x := 5 % 18
	println(x)
	var origValue = "swqedq"
	paramValue := origValue[:1] + "'||'" + origValue[1:]
	println(paramValue)
}
