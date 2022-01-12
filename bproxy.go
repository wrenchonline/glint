package main

import (
	"bufio"
	"glint/logger"
	"net"
	"net/http"
	"regexp"
	"strconv"

	"github.com/elazarl/goproxy"
)

type Proxy struct {
	port int
}

func (p *Proxy) init() error {
	var err error
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	http.ListenAndServe(":"+strconv.Itoa(p.port), proxy)

	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:443$"))).
		HandleConnect(goproxy.AlwaysReject)
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:80$"))).
		HijackConnect(func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
			// defer func() {
			// 	if e := recover(); e != nil {
			// 		ctx.Logf("error connecting to remote: %v", e)
			// 		client.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
			// 	}
			// 	client.Close()
			// }()
			clientBuf := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
			remote, err := net.Dial("tcp", req.URL.Host)
			if err != nil {
				panic(err)
			}

			client.Write([]byte("HTTP/1.1 200 Ok\r\n\r\n"))
			remoteBuf := bufio.NewReadWriter(bufio.NewReader(remote), bufio.NewWriter(remote))
			for {
				req, err := http.ReadRequest(clientBuf.Reader)
				if err != nil {
					panic(err)
				}

				err = req.Write(remoteBuf)
				if err != nil {
					panic(err)
				}
				err = remoteBuf.Flush()
				if err != nil {
					panic(err)
				}

				resp, err := http.ReadResponse(remoteBuf.Reader, req)
				if err != nil {
					panic(err)
				}
				err = resp.Write(clientBuf.Writer)
				if err != nil {
					panic(err)
				}

				logger.Info("resp %v", resp)
			}
		})
	return err
}
