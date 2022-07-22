package main

import (
	"fmt"
	"glint/config"
	"glint/pkg/pocs/crlf"
	"glint/plugin"
	"glint/util"
	"sync"
	"testing"
	"time"
)

func Test_Crlf(t *testing.T) {
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/crlf_test.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, crlf.Crlf)
	pluginInternal := plugin.Plugin{
		PluginName:   "Crlf",
		PluginId:     plugin.Crlf,
		MaxPoolCount: 20,
		Callbacks:    myfunc,
		Timeout:      200 * time.Second,
	}
	pluginInternal.Init()
	PluginWg.Add(1)
	Progress := 0.
	Ratelimite := util.Rate{}
	Ratelimite.InitRate(500)
	args := plugin.PluginOption{
		PluginWg: &PluginWg,
		Progress: &Progress,
		IsSocket: false,
		Data:     data,
		TaskId:   999,
		Rate:     &Ratelimite,
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}
