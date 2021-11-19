package crawler

import (
	"sync"
	"wenscan/model"

	"github.com/panjf2000/ants/v2"
)

type Result struct {
	ReqList       []*model.Request // 返回的同域名结果
	AllReqList    []*model.Request // 所有域名的请求
	AllDomainList []string         // 所有域名列表
	SubDomainList []string         // 子域名列表
	resultLock    sync.Mutex       // 合并结果时加锁
}

type CrawlerTask struct {
	Browser    *Spider          //
	RootDomain string           // 当前爬取根域名 用于子域名收集
	Targets    []*model.Request // 输入目标
	Result     *Result          // 最终结果
	// Config        *TaskConfig      // 配置信息
	smartFilter   SmartFilter    // 过滤对象
	Pool          *ants.Pool     // 协程池
	taskWG        sync.WaitGroup // 等待协程池所有任务结束
	crawledCount  int            // 爬取过的数量
	taskCountLock sync.Mutex     // 已爬取的任务总数锁
}
