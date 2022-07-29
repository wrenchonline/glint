package main

import (
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/pkg/pocs/directorytraversal"
	"glint/plugin"
	"glint/util"
	"sync"
	"testing"
	"time"
)

func Test_TraversalVaild(t *testing.T) {
	logger.DebugEnable(false)
	// go func() {
	// 	ip := "0.0.0.0:6060"
	// 	if err := http.ListenAndServe(ip, nil); err != nil {
	// 		fmt.Printf("start pprof failed on %s\n", ip)
	// 	}
	// }()

	//Spider := nenet.Spider{}
	var taskconfig config.TaskYamlConfig
	taskconfig.Qps = 500
	taskconfig.Proxy = "127.0.0.1:7777" //taskconfig.Proxy = "127.0.0.1:7777"
	Config := config.TaskConfig{Yaml: &taskconfig}
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/directoryTraversal_test.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, directorytraversal.TraversalVaild)
	pluginInternal := plugin.Plugin{
		PluginName:   "directoryTraversal",
		PluginId:     plugin.DIR_COSS,
		MaxPoolCount: 5,

		// Callbacks:    myfunc,
		// Spider:  &Spider,
		Timeout: time.Second * 9999,
	}
	pluginInternal.Init()
	pluginInternal.Callbacks = myfunc
	PluginWg.Add(1)
	Progress := 0.0
	Ratelimite := util.Rate{}
	Ratelimite.InitRate(500)
	args := plugin.PluginOption{
		PluginWg: &PluginWg,
		Progress: &Progress,
		IsSocket: false,
		Data:     data,
		TaskId:   999,
		Rate:     &Ratelimite,
		Config:   &Config,
		// Config:
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}
