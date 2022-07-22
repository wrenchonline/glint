package main

import (
	"fmt"
	"glint/config"
	"glint/pkg/pocs/ssrfcheck"
	"glint/plugin"
	"glint/util"
	"sync"
	"testing"
	"time"
)

func Test_ssrf(t *testing.T) {

	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/sql_error.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, ssrfcheck.Ssrf)
	pluginInternal := plugin.Plugin{
		PluginName:   "SSRF",
		PluginId:     plugin.Ssrf,
		MaxPoolCount: 5,
		Callbacks:    myfunc,
		Timeout:      30 * time.Second,
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
