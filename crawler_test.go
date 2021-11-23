package main

import (
	"testing"
	craw "wenscan/crawler"
)

func Test_Crawler(t *testing.T) {

	// results := []ast.Groups{}

	// List := make(map[string][]ast.JsonUrl)
	// funk.Map(tab.ResultList, func(r *model2.Request) bool {
	// 	element := ast.JsonUrl{
	// 		Url:     r.URL.String(),
	// 		MetHod:  r.Method,
	// 		Headers: r.Headers,
	// 		Data:    r.PostData,
	// 		Source:  r.Source}
	// 	List[r.GroupsId] = append(List[r.GroupsId], element)
	// 	return false
	// })
	// data, err := json.Marshal(List)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// err = ioutil.WriteFile("./result.json", data, 666)
	// if err != nil {
	// 	log.Fatal(err)
	// }

}

func Test_filter(t *testing.T) {
	const url = `https://ka-f.fontawesome.com/releases/v5.15.4/webfonts/free-fa-solid-900.woff2`
	if craw.FilterKey(url, craw.ForbidenKey) {
	} else {
		t.Errorf("test FilterKey() fail")
	}
}
