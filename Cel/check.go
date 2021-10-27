package cel

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"wenscan/utils"

	color "github.com/logrusorgru/aurora"
)

var (
	ceyeApi    string
	ceyeDomain string
)

type Task struct {
	Req *http.Request
	Poc *Poc
}

func InitCeyeApi(api, domain string) bool {
	if api == "" || domain == "" || !strings.HasSuffix(domain, ".ceye.io") {
		return false
	}
	ceyeApi = api
	ceyeDomain = domain
	return true
}

func checkVul(tasks []Task, ticker *time.Ticker) <-chan Task {
	var wg sync.WaitGroup
	results := make(chan Task)
	for _, task := range tasks {
		wg.Add(1)
		go func(task Task) {
			defer wg.Done()
			<-ticker.C
			isVul, err := executePoc(task.Req, task.Poc)
			if err != nil {
				fmt.Println(color.Red(err))
				// utils.Error(err)
				return
			}
			if isVul {
				results <- task
			}
		}(task)
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}

func BatchCheckSinglePoc(targets []string, pocName string, rate int) {
	if p, err := LoadSinglePoc(pocName); err == nil {
		rateLimit := time.Second / time.Duration(rate)
		ticker := time.NewTicker(rateLimit)
		defer ticker.Stop()
		var tasks []Task
		for _, target := range targets {
			req, _ := http.NewRequest("GET", target, nil)
			task := Task{
				Req: req,
				Poc: p,
			}
			tasks = append(tasks, task)
		}
		for result := range checkVul(tasks, ticker) {
			fmt.Println(result.Req.URL, result.Poc.Name)
		}
	}
}

func BatchCheckMultiPoc(targets []string, pocName string, threads, rate int) {
	pocs := LoadMultiPoc(pocName)
	rateLimit := time.Second / time.Duration(rate)
	ticker := time.NewTicker(rateLimit)
	defer ticker.Stop()

	in := make(chan string)
	go func() {
		for _, target := range targets {
			in <- target
		}
		close(in)
	}()

	worker := func(targets <-chan string, wg *sync.WaitGroup, retCh chan<- []Task) {
		defer wg.Done()
		for target := range targets {
			var tasks []Task
			var results []Task
			req, _ := http.NewRequest("GET", target, nil)
			for _, poc := range pocs {
				task := Task{
					Req: req,
					Poc: poc,
				}
				tasks = append(tasks, task)
			}
			for result := range checkVul(tasks, ticker) {
				results = append(results, result)
			}
			retCh <- results
		}
	}

	do := func() <-chan []Task {
		var wg sync.WaitGroup
		retCh := make(chan []Task, threads)
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go worker(in, &wg, retCh)
		}
		go func() {
			wg.Wait()
			close(retCh)
		}()
		return retCh
	}
	for results := range do() {
		for _, result := range results {
			fmt.Println(color.Sprintf("%s %s", color.Green(result.Req.URL), color.Green(result.Poc.Name)))
			// utils.Green("%s %s", result.Req.URL, result.Poc.Name)
		}
	}
}

func CheckSinglePoc(req *http.Request, pocName string) *Poc {
	if p, err := LoadSinglePoc(pocName); err == nil {
		if isVul, err := executePoc(req, p); err == nil {
			if isVul {
				return p
			}
		}
	}
	return nil
}

func CheckMultiPoc(req *http.Request, pocName string, rate int) {
	rateLimit := time.Second / time.Duration(rate)
	ticker := time.NewTicker(rateLimit)
	defer ticker.Stop()
	var tasks []Task
	for _, poc := range LoadMultiPoc(pocName) {
		task := Task{
			Req: req,
			Poc: poc,
		}
		tasks = append(tasks, task)
	}
	for result := range checkVul(tasks, ticker) {
		fmt.Println(color.Sprintf("%s %s", color.Green(result.Req.URL), color.Green(result.Poc.Name)))
		// utils.Green("%s %s", result.Req.URL, result.Poc.Name)
	}
}

func executePoc(oReq *http.Request, p *Poc) (bool, error) {
	fmt.Println(color.Sprintf("%s %s", color.Cyan(oReq.URL.String()), color.Cyan(p.Name)))
	// utils.Debug(oReq.URL.String(), p.Name)
	c := NewEnvOption()
	c.UpdateCompileOptions(p.Set)
	env, err := NewEnv(&c)
	if err != nil {
		fmt.Println(color.Sprintf("environment creation error: %s\n", color.Red(err)))
		//utils.ErrorF("environment creation error: %s\n", err)
		return false, err
	}
	variableMap := make(map[string]interface{})
	req, err := ParseRequest(oReq)
	if err != nil {
		fmt.Println(color.Sprintf("%s\n", color.Red(err)))
		// utils.Error(err)
		return false, err
	}
	variableMap["request"] = req

	// 现在假定set中payload作为最后产出，那么先排序解析其他的自定义变量，更新map[string]interface{}后再来解析payload
	keys := make([]string, 0)
	for k := range p.Set {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		expression := p.Set[k]
		if k != "payload" {
			if expression == "newReverse()" {
				variableMap[k] = newReverse()
				continue
			}
			out, err := Evaluate(env, expression, variableMap)
			if err != nil {
				fmt.Println(color.Sprintf("%s\n", color.Red(err)))
				continue
			}
			switch value := out.Value().(type) {
			case *UrlType:
				variableMap[k] = UrlTypeToString(value)
			case int64:
				variableMap[k] = int(value)
			default:
				variableMap[k] = fmt.Sprintf("%v", out)
			}
		}
	}

	if p.Set["payload"] != "" {
		out, err := Evaluate(env, p.Set["payload"], variableMap)
		if err != nil {
			return false, err
		}
		variableMap["payload"] = fmt.Sprintf("%v", out)
	}

	success := false
	for _, rule := range p.Rules {
		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range rule.Headers {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
		}

		if oReq.URL.Path != "" && oReq.URL.Path != "/" {
			req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
		} else {
			req.Url.Path = rule.Path
		}
		// 某些poc没有区分path和query，需要处理
		req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")
		req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")

		newRequest, _ := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(rule.Body))
		newRequest.Header = oReq.Header.Clone()
		for k, v := range rule.Headers {
			newRequest.Header.Set(k, v)
		}
		resp, err := DoRequest(newRequest, rule.FollowRedirects)
		if err != nil {
			return false, err
		}
		variableMap["response"] = resp

		// 先判断响应页面是否匹配search规则
		if rule.Search != "" {
			result := doSearch(strings.TrimSpace(rule.Search), string(resp.Body))
			if result != nil && len(result) > 0 { // 正则匹配成功
				for k, v := range result {
					variableMap[k] = v
				}
				//return false, nil
			} else {
				return false, nil
			}
		}

		out, err := Evaluate(env, rule.Expression, variableMap)
		if err != nil {
			return false, err
		}
		//fmt.Println(fmt.Sprintf("%v, %s", out, out.Type().TypeName()))
		if fmt.Sprintf("%v", out) == "false" { //如果false不继续执行后续rule
			success = false // 如果最后一步执行失败，就算前面成功了最终依旧是失败
			break
		}
		success = true
	}
	return success, nil
}

func doSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	if err != nil {
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				paramsMap[name] = result[i]
			}
		}
		return paramsMap
	}
	return nil
}

func newReverse() *Reverse {
	letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	randSource := rand.New(rand.NewSource(time.Now().Unix()))
	sub := utils.RandomStr(randSource, letters, 8)
	if ceyeDomain == "" {
		return &Reverse{}
	}
	urlStr := fmt.Sprintf("http://%s.%s", sub, ceyeDomain)
	u, _ := url.Parse(urlStr)
	return &Reverse{
		Url:                ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}
