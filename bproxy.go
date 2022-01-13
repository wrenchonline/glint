package main

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/google/martian/v3"
)

type Proxy struct {
	port int
}

var (
	addr           = flag.String("addr", ":8080", "host:port of the proxy")
	apiAddr        = flag.String("api-addr", ":8181", "host:port of the configuration API")
	tlsAddr        = flag.String("tls-addr", ":4443", "host:port of the proxy over TLS")
	api            = flag.String("api", "martian.proxy", "hostname for the API")
	generateCA     = flag.Bool("generate-ca-cert", false, "generate CA certificate and private key for MITM")
	cert           = flag.String("cert", "", "filepath to the CA certificate used to sign MITM certificates")
	key            = flag.String("key", "", "filepath to the private key of the CA used to sign MITM certificates")
	organization   = flag.String("organization", "Martian Proxy", "organization name for MITM certificates")
	validity       = flag.Duration("validity", time.Hour, "window of time that MITM certificates are valid")
	allowCORS      = flag.Bool("cors", false, "allow CORS requests to configure the proxy")
	harLogging     = flag.Bool("har", false, "enable HAR logging API")
	marblLogging   = flag.Bool("marbl", false, "enable MARBL logging API")
	trafficShaping = flag.Bool("traffic-shaping", false, "enable traffic shaping API")
	skipTLSVerify  = flag.Bool("skip-tls-verify", false, "skip TLS server verification; insecure")
	dsProxyURL     = flag.String("downstream-proxy-url", "", "URL of downstream proxy")
)

func (p *Proxy) init() error {
	martian.Init()
	proxy := martian.NewProxy()
	defer proxy.Close()
	lAPI, err := net.Listen("tcp", *apiAddr)
	if err != nil {
		log.Fatal(err)
	}
	go proxy.Serve(lAPI)
	return nil
}
