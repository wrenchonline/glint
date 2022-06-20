package main

import (
	"fmt"
	"glint/brohttp"
	"glint/config"
	"glint/logger"
	"glint/pkg/pocs/xsschecker"
	"glint/plugin"
	"regexp"
	"sync"
	"testing"
	"time"
)

func Test_regex(t *testing.T) {
	regexstr := `(?i)(SQL[\s\S]error[\s\S]*)`
	r, _ := regexp.Compile(regexstr)
	C := r.FindAllStringSubmatch("SQL ERROR: syntax error at or near", -1)
	if len(C) != 0 {
		fmt.Println("sinks match")
	}
}

func TestAppError(t *testing.T) {
	logger.DebugEnable(false)
	// go func() {
	// 	ip := "0.0.0.0:6060"
	// 	if err := http.ListenAndServe(ip, nil); err != nil {
	// 		fmt.Printf("start pprof failed on %s\n", ip)
	// 	}
	// }()

	Spider := brohttp.Spider{}
	var taskconfig config.TaskConfig
	taskconfig.Proxy = "" //taskconfig.Proxy = "127.0.0.1:7777"
	err := Spider.Init(taskconfig)
	if err != nil {
		t.Fatal(err)
	}
	defer Spider.Close()
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_file/xss_test2.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, xsschecker.CheckXss)

	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	pluginInternal := plugin.Plugin{
		PluginName:   "APPERR",
		PluginId:     plugin.Xss,
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
		PluginWg: &PluginWg,
		Progress: &Progress,
		IsSocket: false,
		Data:     data,
		TaskId:   999,
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}
