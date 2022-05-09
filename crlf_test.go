package main

import (
	"fmt"
	"glint/config"
	"glint/crlf"
	"glint/plugin"
	"sync"
	"testing"
	"time"
)

func Test_Crlf(t *testing.T) {
	data := make(map[string][]interface{})
	var PluginWg sync.WaitGroup
	config.ReadResultConf("result2.json", &data)
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
