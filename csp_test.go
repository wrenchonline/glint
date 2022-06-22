package main

import (
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/pkg/pocs/cspnotimplement"
	"glint/plugin"
	"sync"
	"testing"
	"time"
)

func TestCSP(t *testing.T) {
	logger.DebugEnable(false)
	// go func() {
	// 	ip := "0.0.0.0:6060"
	// 	if err := http.ListenAndServe(ip, nil); err != nil {
	// 		fmt.Printf("start pprof failed on %s\n", ip)
	// 	}
	// }()

	//Spider := brohttp.Spider{}
	var taskconfig config.TaskConfig
	taskconfig.Proxy = "" //taskconfig.Proxy = "127.0.0.1:7777"
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_file/csp.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, cspnotimplement.CSPStartTest)

	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	pluginInternal := plugin.Plugin{
		PluginName:   "APPERR",
		PluginId:     plugin.CSP,
		MaxPoolCount: 1,
		// Callbacks:    myfunc,
		Spider:  nil,
		Timeout: time.Second * 999,
	}
	pluginInternal.Init()
	pluginInternal.Callbacks = myfunc
	PluginWg.Add(1)
	Progress := 0.0
	args := plugin.PluginOption{
		PluginWg:      &PluginWg,
		Progress:      &Progress,
		IsSocket:      false,
		Data:          data,
		TaskId:        999,
		IsAllUrlsEval: true,
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}
