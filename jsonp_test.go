package main

import (
	"fmt"

	"glint/config"
	"glint/jsonp"
	"glint/plugin"
	"sync"
	"testing"
	"time"
)

func Test_Jsonp(t *testing.T) {
	data := make(map[string][]interface{})
	var PluginWg sync.WaitGroup
	config.ReadResultConf("result.json", &data)
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, jsonp.JsonpValid)
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
	args := plugin.PluginOption{
		PluginWg: &PluginWg,
		Progress: &Progress,
		IsSocket: false,
		Data:     data,
		TaskId:   999,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}
