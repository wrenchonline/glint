package plugin

import (
	"fmt"
	"sync"

	"github.com/panjf2000/ants/v2"
)

type Plugin struct {
	MaxPoolCount int              //协程池最大并发数
	Callbacks    []PluginCallback //扫描插件函数
	poolfunc     *ants.PoolWithFunc
	Threadwg     sync.WaitGroup //同步线程
}

type GroupData struct {
	GroupType string
	GroupUrls []interface{}
}

func (p *Plugin) Init() {
	p.poolfunc, _ = ants.NewPoolWithFunc(p.MaxPoolCount, func(args interface{}) { //新建一个带有同类方法的pool对象
		defer p.Threadwg.Done()
		data := args.(GroupData)
		for _, f := range p.Callbacks {
			f(data)
		}
	})
}

type PluginCallback func(args interface{}) error

func (p *Plugin) Run(data map[string][]interface{}, PluginWg *sync.WaitGroup) error {
	defer PluginWg.Done()
	defer p.poolfunc.Release()
	var err error
	for k, v := range data {
		p.Threadwg.Add(1)
		go func() {
			data := GroupData{GroupType: k, GroupUrls: v}
			err = p.poolfunc.Invoke(data)
			if err != nil {
				println(err.Error())
			}
		}()
	}
	p.Threadwg.Wait()
	fmt.Println("ok")
	return err
}
