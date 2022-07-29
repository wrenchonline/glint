package main

import (
	"bufio"
	"fmt"
	"glint/ast"
	"glint/nenet"

	"glint/config"
	"glint/logger"
	"glint/model"
	"glint/pkg/pocs/xsschecker"
	"glint/plugin"
	"glint/util"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/martian/v3/har"
	"github.com/k0kubun/go-ansi"
	. "github.com/logrusorgru/aurora"
	"github.com/mitchellh/colorstring"
	"github.com/thoas/go-funk"
	"github.com/valyala/bytebufferpool"
)

func TestXSS(t *testing.T) {
	logger.DebugEnable(false)
	// go func() {
	// 	ip := "0.0.0.0:6060"
	// 	if err := http.ListenAndServe(ip, nil); err != nil {
	// 		fmt.Printf("start pprof failed on %s\n", ip)
	// 	}
	// }()

	Spider := nenet.Spider{}
	var taskconfig config.TaskYamlConfig
	taskconfig.Qps = 500
	taskconfig.Proxy = "" //taskconfig.Proxy = "127.0.0.1:7777"
	err := Spider.Init(taskconfig)
	if err != nil {
		t.Fatal(err)
	}
	defer Spider.Close()
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/xss_test2.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, xsschecker.CheckXss)

	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	pluginInternal := plugin.Plugin{
		PluginName:   "XSS",
		PluginId:     plugin.Xss,
		MaxPoolCount: 1,
		// Callbacks:    myfunc,
		Spider:  &Spider,
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
	Spider := nenet.Spider{}

	var taskconfig config.TaskYamlConfig
	taskconfig.Proxy = ""
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
	tabs_obj, _ := nenet.NewTabsOBJ(&Spider)
	tabs_obj.CopyRequest(a)
	tabs_obj.Send()
	time.Sleep(5 * time.Second)
	tabs_obj.Send()
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

type httpWriter interface {
	Write(w *bufio.Writer) error
}

func getHTTPString(hw httpWriter) string {
	w := bytebufferpool.Get()
	bw := bufio.NewWriter(w)
	if err := hw.Write(bw); err != nil {
		return err.Error()
	}
	if err := bw.Flush(); err != nil {
		return err.Error()
	}
	s := string(w.B)
	bytebufferpool.Put(w)
	return s
}

func Test_har_log(t *testing.T) {

	var nhreq har.Request
	nhreq.HTTPVersion = "HTTP/1.1"
	nhreq.Method = "POST"
	nhreq.URL = "http://localhost:5451"
	req, _ := http.NewRequest("GET", "http://api.themoviedb.org/3/tv/popular", nil)
	req.Header.Add("Accept", "application/json")
	// getHTTPString(&req)
	// httputil.DumpRequest()

}
func Test_url_parse(t *testing.T) {

	s := "http://api.themoviedb.org/3/tv/popular"

	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	fmt.Println(u.Hostname())

	mu := model.URL{*u}
	fmt.Println(mu.RootDomain())

	fmt.Println(u.Scheme)

	r, _ := http.NewRequest("GET", "http://localhost/slow/one.json", nil)
	fmt.Println(path.Base(r.URL.Path))

}
