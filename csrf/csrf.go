package csrf

import (
	"fmt"
	"wenscan/config"

	"github.com/valyala/fasthttp"
)

func Origin(k string, v []interface{}) error {
	ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	for _, url := range v {
		fastReq := fasthttp.AcquireRequest()
		err := config.CopyConfReq(url, fastReq)
		if err != nil {
			return err
		}
		resp := &fasthttp.Response{}
		client := &fasthttp.Client{}
		if err := client.Do(fastReq, resp); err != nil {
			fmt.Println("request fail:", err.Error())
			return err
		}
		b1 := resp.Body()
		fastReq2 := fasthttp.AcquireRequest()
		fastReq.CopyTo(fastReq2)
		fastReq2.Header.Set("Origin", ORIGIN_URL)
		client2 := &fasthttp.Client{}
		if err := client2.Do(fastReq, resp); err != nil {
			fmt.Println("request fail:", err.Error())
			return err
		}
		b2 := resp.Body()
		if len(b1) == len(b2) {
			fmt.Println("Heuristics reveal endpoint might be VULNERABLE to Origin Based CSRFs...")
		}
	}
	return nil
}
