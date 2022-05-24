package crawler

import (
	"context"
	"fmt"
	"glint/fastreq"
	"glint/logger"
	model2 "glint/model"
	"glint/util"
	"regexp"
	"strings"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/logrusorgru/aurora"
	"github.com/panjf2000/ants/v2"
)

const pathStr = "dfish_sso/11/123/2017/2018/message/mis/model/abstract/account/act/action" +
	"/activity/ad/address/ajax/alarm/api/app/ar/attachment/auth/authority/award/back/backup/bak/base" +
	"/bbs/bbs1/cms/bd/gallery/game/gift/gold/bg/bin/blacklist/blog/bootstrap/brand/build/cache/caches" +
	"/caching/cacti/cake/captcha/category/cdn/ch/check/city/class/classes/classic/client/cluster" +
	"/collection/comment/commit/common/commons/components/conf/config/mysite/confs/console/consumer" +
	"/content/control/controllers/core/crontab/crud/css/daily/dashboard/data/database/db/default/demo" +
	"/dev/doc/download/duty/es/eva/examples/excel/export/ext/fe/feature/file/files/finance/flashchart" +
	"/follow/forum/frame/framework/ft/group/gss/hello/helper/helpers/history/home/hr/htdocs/html/hunter" +
	"/image/img11/import/improve/inc/include/includes/index/info/install/interface/item/jobconsume/jobs" +
	"/json/kindeditor/l/languages/lib/libraries/libs/link/lite/local/log/login/logs/mail/main" +
	"/maintenance/manage/manager/manufacturer/menus/models/modules/monitor/movie/mysql/n/nav/network" +
	"/news/notice/nw/oauth/other/page/pages/passport/pay/pcheck/people/person/php/phprpc" +
	"/phptest/picture/pl/platform/pm/portal/post/product/project/protected/proxy/ps/public/qq/question" +
	"/quote/redirect/redisclient/report/resource/resources/s/save/schedule/schema/script/scripts/search" +
	"/security/server/service/shell/show/simple/site/sites/skin/sms/soap/sola/sort/spider/sql/stat" +
	"/static/statistics/stats/submit/subways/survey/sv/syslog/system/tag/task/tasks/tcpdf/template" +
	"/templates/test/tests/ticket/tmp/token/tool/tools/top/tpl/txt/upload/uploadify/uploads/url/user" +
	"/util/v1/v2/vendor/view/views/web/weixin/widgets/wm/wordpress/workspace/ws/www/www2/wwwroot/zone" +
	"/admin/admin_bak/mobile/m/js"

var pathFuzzWG sync.WaitGroup
var validateUrl mapset.Set

/**
从robots.txt文件中获取路径信息
*/
func GetPathsFromRobots(navReq model2.Request) []*model2.Request {
	logger.Info("starting to get paths from robots.txt.")
	var result []*model2.Request
	var urlFindRegex = regexp.MustCompile(`(?:Disallow|Allow):.*?(/.+)`)
	var urlRegex = regexp.MustCompile(`(/.+)`)

	navReq.URL.Path = "/"
	url := navReq.URL.NoQueryUrl() + "robots.txt"
	headers, _ := util.ConvertHeaders(navReq.Headers)
	_, resp, err := fastreq.Get(url, headers,
		&fastreq.ReqOptions{AllowRedirect: false,
			Timeout: 5 * time.Second,
			Proxy:   navReq.FasthttpProxy})
	if err != nil {
		//for
		//logger.Logger.Error("request to robots.txt error ", err)
		return result
	}

	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return result
	}
	urlList := urlFindRegex.FindAllString(resp.String(), -1)
	for _, _url := range urlList {
		_url = strings.TrimSpace(_url)
		_url = urlRegex.FindString(_url)
		url, err := model2.GetUrl(_url, *navReq.URL)
		if err != nil {
			continue
		}
		req := model2.GetRequest("GET", url)
		req.Source = "robots.txt"
		result = append(result, &req)
	}
	return result
}

/**
使用常见路径列表进行fuzz
*/
func GetPathsByFuzz(navReq model2.Request, ctx context.Context) []*model2.Request {
	logger.Info("starting to get paths by fuzzing.")
	pathList := strings.Split(pathStr, "/")
	return doFuzz(navReq, pathList, ctx)
}

/**
使用字典列表进行fuzz
*/
func GetPathsByFuzzDict(navReq model2.Request, dictPath string, ctx context.Context) []*model2.Request {
	logger.Info("starting to get dict path by fuzzing: %s", dictPath)
	pathList := util.ReadFile(dictPath)
	logger.Debug("valid path count: %d", len(pathList))
	return doFuzz(navReq, pathList, ctx)
}

type singleFuzz struct {
	navReq model2.Request
	path   string
	Ctx    *context.Context
	Cancel *context.CancelFunc
}

func doFuzz(navReq model2.Request, pathList []string, ctx context.Context) []*model2.Request {
	validateUrl = mapset.NewSet()
	var result []*model2.Request
	pool, _ := ants.NewPool(20)
	defer pool.Release()
	for _, path := range pathList {
		path = strings.TrimPrefix(path, "/")
		path = strings.TrimSuffix(path, "\n")
		task := singleFuzz{
			navReq: navReq,
			path:   path,
			Ctx:    &ctx,
		}
		pathFuzzWG.Add(1)
		go func() {
			err := pool.Submit(task.doRequest)
			if err != nil {
				pathFuzzWG.Done()
			}
		}()
	}

	pathFuzzWG.Wait()
	for _, _url := range validateUrl.ToSlice() {
		_url := _url.(string)
		url, err := model2.GetUrl(_url)
		if err != nil {
			continue
		}
		req := model2.GetRequest("GET", url)
		req.Source = "PathFuzz"
		result = append(result, &req)
	}
	return result
}

/**

 */
func (s singleFuzz) doRequest() {
	defer pathFuzzWG.Done()
	select {
	case <-(*s.Ctx).Done():
		return
	default:
	}
	url := fmt.Sprintf(`%s://%s/%s`, s.navReq.URL.Scheme, s.navReq.URL.Host, s.path)
	headers, _ := util.ConvertHeaders(s.navReq.Headers)
	_, resp, errs := fastreq.Get(url, headers,
		&fastreq.ReqOptions{Timeout: 2 * time.Second, AllowRedirect: true, Proxy: s.navReq.FasthttpProxy})
	if errs != nil {
		// logger.Info("doRequest err: %s", errs.Error())
		return
	}
	if resp.StatusCode() >= 200 && resp.StatusCode() < 300 {
		validateUrl.Add(url)
	} else if resp.StatusCode() == 301 || resp.StatusCode() == 302 {
		validateUrl.Add(url)
		Header := resp.Header.String()
		fmt.Println(aurora.Magenta(Header))
		// locations := resp.Header["Location"]
		// if len(locations) == 0 {
		// 	return
		// }
		// location := locations[0]
		// redirectUrl, err := model2.GetUrl(location)
		// if err != nil {
		// 	return
		// }
		// if redirectUrl.Host == s.navReq.URL.Host {
		// 	validateUrl.Add(url)
		// }
	}
}
