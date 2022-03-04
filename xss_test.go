package main

import (
	"fmt"
	"glint/ast"
	brohttp "glint/brohttp"
	"glint/config"
	"glint/logger"
	"glint/plugin"
	"glint/xsschecker"
	"net/http"
	_ "net/http/pprof"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/k0kubun/go-ansi"
	. "github.com/logrusorgru/aurora"
	"github.com/mitchellh/colorstring"
	"github.com/thoas/go-funk"
)

func TestXSS(t *testing.T) {
	logger.DebugEnable(false)
	go func() {
		ip := "0.0.0.0:6060"
		if err := http.ListenAndServe(ip, nil); err != nil {
			fmt.Printf("start pprof failed on %s\n", ip)
		}
	}()

	Spider := brohttp.Spider{}
	var taskconfig config.TaskConfig
	taskconfig.Proxy = "127.0.0.1:7777"
	err := Spider.Init(taskconfig)
	if err != nil {
		t.Fatal(err)
	}
	defer Spider.Close()
	data := make(map[string][]interface{})
	var PluginWg sync.WaitGroup
	config.ReadResultConf("result2.json", &data)
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, xsschecker.CheckXss)
	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	pluginInternal := plugin.Plugin{
		PluginName:   plugin.Xss,
		MaxPoolCount: 20,
		// Callbacks:    myfunc,
		Spider:  &Spider,
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

func TestURL(t *testing.T) {
	logger.DebugEnable(false)
	Spider := brohttp.Spider{}

	var taskconfig config.TaskConfig
	taskconfig.Proxy = "127.0.0.1:7777"
	Spider.Init(taskconfig)

	Headers := make(map[string]interface{})
	Headers["Cookies"] = "welcome=1"
	Headers["Referer"] = "http://35.227.24.107/5c40a9b9c3/index.php"
	defer Spider.Close()
	a := ast.JsonUrl{
		Url:     "http://35.227.24.107/5c40a9b9c3/index.php",
		MetHod:  "GET",
		Headers: Headers,
	}
	tab, _ := brohttp.NewTab(&Spider)
	tab.CopyRequest(a)
	tab.Send()
	time.Sleep(5 * time.Second)
	tab.Send()
	time.Sleep(5 * time.Second)
}
func Test_JS(t *testing.T) {
	io := ansi.NewAnsiStdout()
	logger.DebugEnable(true)
	var sourceFound bool
	var sinkFound bool
	script := ``
	sources := `document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage`
	sinks := `eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location`
	newlines := strings.Split(script, "\n")

	matchsinks := funk.Map(newlines, func(x string) string {
		//parts := strings.Split(x, "var ")
		r, _ := regexp.Compile(sinks)
		C := r.FindAllStringSubmatch(x, -1)
		if len(C) != 0 {
			fmt.Println(Sprintf(Magenta("sinks match :%v \n"), Red(C[0][0])))
			return "vul"
		}
		return ""
	})

	matchsources := funk.Map(newlines, func(x string) string {
		r, _ := regexp.Compile(sources)
		C := r.FindAllStringSubmatch(x, -1)
		if len(C) != 0 {
			fmt.Println(Sprintf(Magenta("sources match :%v \n"), Yellow(C[0][0])))
			return "vul"
		}
		return ""
	})

	if value, ok := matchsources.([]string); ok {
		if funk.Contains(value, "vul") {
			sourceFound = true
		}
	}

	if value, ok := matchsinks.([]string); ok {
		if funk.Contains(value, "vul") {
			sinkFound = true
		}
	}

	if sourceFound && sinkFound {
		colorstring.Fprintf(io, "[red] 发现DOM XSS漏洞,该对应参考payload代码应由研究人员构造 \n")
	}
}
