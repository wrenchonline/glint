package main

import (
	"log"
	"testing"
	cf "wenscan/config"
	craw "wenscan/crawler"
)

func TestCrawler(t *testing.T) {
	Spider := craw.Spider{}
	Spider.Init()
	cf := cf.Conf{}
	Conf := cf.GetConf()

	for _, i := range Conf.Cookies {
		c := Spider.SetCookie(i.Name, i.Value, i.Domain, i.Path, i.HttpOnly, i.Secure)
		Spider.Cookies = append(Spider.Cookies, c)
	}

	Spider.Scanhostpage = Conf.Crawler.Url[0]
	Spider.ForbiddenUrl = Conf.Crawler.Brokenurl

	ctx, _, err := Spider.Crawler(Spider.Scanhostpage, nil)

	Requests := Spider.Requests
	for _, Request := range Requests {
		if _, ok := ctx.Deadline(); ok {
			log.Println("Ctx is Deadline")
			break
		}
		if _, _, err := Spider.Crawler(Request.URL, ctx); err != nil {
			log.Println("Crawler error:", err)
		} else {

		}
	}
	log.Println("program quit:", err)

}
