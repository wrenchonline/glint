package main

import (
	"fmt"
	"glint/config"
	"glint/pkg/pocs/ssrfcheck"
	"glint/plugin"
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
