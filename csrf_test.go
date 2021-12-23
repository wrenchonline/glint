package main

import (
	"fmt"
	"glint/config"
	"glint/csrf"
	"glint/plugin"
	"sync"
	"testing"
	"time"
)

func Test_CSRF(t *testing.T) {
	data := make(map[string][]interface{})
	var PluginWg sync.WaitGroup
	config.ReadResultConf("result.json", &data)
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, csrf.Origin, csrf.Referer)
	plugin := plugin.Plugin{
		PluginName:   "csrf",
		MaxPoolCount: 5,
		Callbacks:    myfunc,
		Timeout:      30 * time.Second,
	}
	plugin.Init()
	PluginWg.Add(1)
	progress := 0
	go func() {
		plugin.Run(data, &PluginWg, &progress)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}
