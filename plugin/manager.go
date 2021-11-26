package plugin

import (
	"glint/brohttp"
	"glint/log"
	"glint/util"
	"sync"

	"github.com/panjf2000/ants/v2"
)

type Plugin struct {
	PluginName   string           //插件名
	MaxPoolCount int              //协程池最大并发数
	Callbacks    []PluginCallback //扫描插件函数
	poolfunc     *ants.PoolWithFunc
	threadwg     sync.WaitGroup //同步线程
	ScanResult   []*util.ScanResult
	mu           sync.Mutex
	Spider       *brohttp.Spider
}

type GroupData struct {
	GroupType string
	GroupUrls []interface{}
	Spider    *brohttp.Spider
}

func (p *Plugin) Init() {
	p.poolfunc, _ = ants.NewPoolWithFunc(p.MaxPoolCount, func(args interface{}) { //新建一个带有同类方法的pool对象
		defer p.threadwg.Done()
		data := args.(GroupData)
		for _, f := range p.Callbacks {
			p.mu.Lock()
			scanresult, err := f(data)
			if err != nil {
				log.Error(err.Error())
			}
			p.ScanResult = append(p.ScanResult, scanresult)
			p.mu.Unlock()
		}
	})
}

type PluginCallback func(args interface{}) (*util.ScanResult, error)

func (p *Plugin) Run(data map[string][]interface{}, PluginWg *sync.WaitGroup) error {
	defer PluginWg.Done()
	defer p.poolfunc.Release()
	var err error
	for k, v := range data {
		p.threadwg.Add(1)
		go func() {
			data := GroupData{GroupType: k, GroupUrls: v, Spider: p.Spider}
			err = p.poolfunc.Invoke(data)
			if err != nil {
				log.Error(err.Error())
			}
		}()
	}
	p.threadwg.Wait()
	log.Info("Plugin %s is Finish!", p.PluginName)

	return err
}
