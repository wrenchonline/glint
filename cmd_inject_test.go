package main

import (
	"fmt"
	"glint/config"
	"glint/pkg/pocs/cmdinject"
	"glint/plugin"
	"glint/util"
	"sync"
	"testing"
	"time"
)

func Test_Cmd_Inject(t *testing.T) {
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("result.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, cmdinject.CmdValid)
	pluginInternal := plugin.Plugin{
		PluginName:   "JSONP",
		PluginId:     plugin.Jsonp,
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
