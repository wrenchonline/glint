package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"glint/logger"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/martian/messageview"
	"github.com/google/martian/v3"
	mapi "github.com/google/martian/v3/api"
	"github.com/google/martian/v3/cors"
	"github.com/google/martian/v3/fifo"
	"github.com/google/martian/v3/har"
	"github.com/google/martian/v3/httpspec"
	"github.com/google/martian/v3/marbl"
	"github.com/google/martian/v3/martianhttp"
	"github.com/google/martian/v3/martianlog"
	"github.com/google/martian/v3/mitm"
	"github.com/google/martian/v3/parse"
	"github.com/google/martian/v3/servemux"
	"github.com/google/martian/v3/trafficshape"
	"github.com/google/martian/v3/verify"
)

type SProxy struct {
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
	harLogging     = flag.Bool("har", true, "enable HAR logging API")
	marblLogging   = flag.Bool("marbl", false, "enable MARBL logging API")
	trafficShaping = flag.Bool("traffic-shaping", false, "enable traffic shaping API")
	skipTLSVerify  = flag.Bool("skip-tls-verify", false, "skip TLS server verification; insecure")
	dsProxyURL     = flag.String("downstream-proxy-url", "", "URL of downstream proxy")
)

func configure(pattern string, handler http.Handler, mux *http.ServeMux) {
	if *allowCORS {
		handler = cors.NewHandler(handler)
	}

	// register handler for martian.proxy to be forwarded to
	// local API server
	mux.Handle(path.Join(*api, pattern), handler)

	// register handler for local API server
	p := path.Join("localhost"+*apiAddr, pattern)
	mux.Handle(p, handler)
}

func (s *SProxy) Init() error {
	martian.Init()

	p := martian.NewProxy()
	defer p.Close()

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	lAPI, err := net.Listen("tcp", *apiAddr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("martian: starting proxy on %s and api on %s", l.Addr().String(), lAPI.Addr().String())

	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *skipTLSVerify,
		},
	}
	p.SetRoundTripper(tr)

	if *dsProxyURL != "" {
		u, err := url.Parse(*dsProxyURL)
		if err != nil {
			log.Fatal(err)
		}
		p.SetDownstreamProxy(u)
	}

	mux := http.NewServeMux()

	var x509c *x509.Certificate
	var priv interface{}

	if *generateCA {
		var err error
		x509c, priv, err = mitm.NewAuthority("martian.proxy", "Martian Authority", 30*24*time.Hour)
		if err != nil {
			log.Fatal(err)
		}
	} else if *cert != "" && *key != "" {
		tlsc, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Fatal(err)
		}
		priv = tlsc.PrivateKey

		x509c, err = x509.ParseCertificate(tlsc.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}
	}

	if x509c != nil && priv != nil {
		mc, err := mitm.NewConfig(x509c, priv)
		if err != nil {
			log.Fatal(err)
		}

		mc.SetValidity(*validity)
		mc.SetOrganization(*organization)
		mc.SkipTLSVerify(*skipTLSVerify)

		p.SetMITM(mc)

		// Expose certificate authority.
		ah := martianhttp.NewAuthorityHandler(x509c)
		configure("/authority.cer", ah, mux)

		// Start TLS listener for transparent MITM.
		tl, err := net.Listen("tcp", *tlsAddr)
		if err != nil {
			log.Fatal(err)
		}

		go p.Serve(tls.NewListener(tl, mc.TLS()))
	}

	stack, fg := httpspec.NewStack("martian")

	// wrap stack in a group so that we can forward API requests to the API port
	// before the httpspec modifiers which include the via modifier which will
	// trip loop detection
	topg := fifo.NewGroup()

	// Redirect API traffic to API server.
	if *apiAddr != "" {
		addrParts := strings.Split(lAPI.Addr().String(), ":")
		apip := addrParts[len(addrParts)-1]
		port, err := strconv.Atoi(apip)
		if err != nil {
			log.Fatal(err)
		}
		host := strings.Join(addrParts[:len(addrParts)-1], ":")

		// Forward traffic that pattern matches in http.DefaultServeMux
		apif := servemux.NewFilter(mux)
		apif.SetRequestModifier(mapi.NewForwarder(host, port))
		topg.AddRequestModifier(apif)
	}
	topg.AddRequestModifier(stack)
	topg.AddResponseModifier(stack)

	p.SetRequestModifier(topg)
	p.SetResponseModifier(topg)

	m := martianhttp.NewModifier()
	fg.AddRequestModifier(m)
	fg.AddResponseModifier(m)

	if *harLogging {
		hl := har.NewLogger()
		muxf := servemux.NewFilter(mux)
		// Only append to HAR logs when the requests are not API requests,
		// that is, they are not matched in http.DefaultServeMux
		muxf.RequestWhenFalse(hl)
		muxf.ResponseWhenFalse(hl)

		stack.AddRequestModifier(muxf)
		stack.AddResponseModifier(muxf)

		configure("/logs", har.NewExportHandler(hl), mux)
		configure("/logs/reset", har.NewResetHandler(hl), mux)
	}

	logger := martianlog.NewLogger()
	logger.SetDecode(true)

	stack.AddRequestModifier(logger)
	stack.AddResponseModifier(logger)

	if *marblLogging {
		lsh := marbl.NewHandler()
		lsm := marbl.NewModifier(lsh)
		muxf := servemux.NewFilter(mux)
		muxf.RequestWhenFalse(lsm)
		muxf.ResponseWhenFalse(lsm)
		stack.AddRequestModifier(muxf)
		stack.AddResponseModifier(muxf)

		// retrieve binary marbl logs
		mux.Handle("/binlogs", lsh)
	}

	// Configure modifiers.
	configure("/configure", m, mux)

	// Verify assertions.
	vh := verify.NewHandler()
	vh.SetRequestVerifier(m)
	vh.SetResponseVerifier(m)
	configure("/verify", vh, mux)

	// Reset verifications.
	rh := verify.NewResetHandler()
	rh.SetRequestVerifier(m)
	rh.SetResponseVerifier(m)
	configure("/verify/reset", rh, mux)

	if *trafficShaping {
		tsl := trafficshape.NewListener(l)
		tsh := trafficshape.NewHandler(tsl)
		configure("/shape-traffic", tsh, mux)
		l = tsl
	}

	go p.Serve(l)

	go http.Serve(lAPI, mux)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)

	<-sigc

	log.Println("martian: shutting down")
	os.Exit(0)
	return nil
}

// Logger is a modifier that logs requests and responses.
type Logger struct {
	log         func(line string)
	headersOnly bool
	decode      bool
}

type loggerJSON struct {
	Scope       []parse.ModifierType `json:"scope"`
	HeadersOnly bool                 `json:"headersOnly"`
	Decode      bool                 `json:"decode"`
}

func init() {
	parse.Register("log.Logger", loggerFromJSON)
}

// NewLogger returns a logger that logs requests and responses, optionally
// logging the body. Log function defaults to martian.Infof.
func NewLogger() *Logger {
	return &Logger{
		log: func(line string) {
			logger.Info(line)
		},
	}
}

// SetHeadersOnly sets whether to log the request/response body in the log.
func (l *Logger) SetHeadersOnly(headersOnly bool) {
	l.headersOnly = headersOnly
}

// SetDecode sets whether to decode the request/response body in the log.
func (l *Logger) SetDecode(decode bool) {
	l.decode = decode
}

// SetLogFunc sets the logging function for the logger.
func (l *Logger) SetLogFunc(logFunc func(line string)) {
	l.log = logFunc
}

// ModifyRequest logs the request, optionally including the body.
//
// The format logged is:
// --------------------------------------------------------------------------------
// Request to http://www.google.com/path?querystring
// --------------------------------------------------------------------------------
// GET /path?querystring HTTP/1.1
// Host: www.google.com
// Connection: close
// Other-Header: values
//
// request content
// --------------------------------------------------------------------------------
func (l *Logger) ModifyRequest(req *http.Request) error {
	ctx := martian.NewContext(req)
	if ctx.SkippingLogging() {
		return nil
	}

	b := &bytes.Buffer{}

	fmt.Fprintln(b, "")
	fmt.Fprintln(b, strings.Repeat("-", 80))
	fmt.Fprintf(b, "Request to %s\n", req.URL)
	fmt.Fprintln(b, strings.Repeat("-", 80))

	mv := messageview.New()
	mv.SkipBody(l.headersOnly)
	if err := mv.SnapshotRequest(req); err != nil {
		return err
	}

	var opts []messageview.Option
	if l.decode {
		opts = append(opts, messageview.Decode())
	}

	r, err := mv.Reader(opts...)
	if err != nil {
		return err
	}

	io.Copy(b, r)

	fmt.Fprintln(b, "")
	fmt.Fprintln(b, strings.Repeat("-", 80))

	l.log(b.String())

	return nil
}

// ModifyResponse logs the response, optionally including the body.
//
// The format logged is:
// --------------------------------------------------------------------------------
// Response from http://www.google.com/path?querystring
// --------------------------------------------------------------------------------
// HTTP/1.1 200 OK
// Date: Tue, 15 Nov 1994 08:12:31 GMT
// Other-Header: values
//
// response content
// --------------------------------------------------------------------------------
func (l *Logger) ModifyResponse(res *http.Response) error {
	ctx := martian.NewContext(res.Request)
	if ctx.SkippingLogging() {
		return nil
	}

	b := &bytes.Buffer{}
	fmt.Fprintln(b, "")
	fmt.Fprintln(b, strings.Repeat("-", 80))
	fmt.Fprintf(b, "Response from %s\n", res.Request.URL)
	fmt.Fprintln(b, strings.Repeat("-", 80))

	mv := messageview.New()
	mv.SkipBody(l.headersOnly)
	if err := mv.SnapshotResponse(res); err != nil {
		return err
	}

	var opts []messageview.Option
	if l.decode {
		opts = append(opts, messageview.Decode())
	}

	r, err := mv.Reader(opts...)
	if err != nil {
		return err
	}

	io.Copy(b, r)

	fmt.Fprintln(b, "")
	fmt.Fprintln(b, strings.Repeat("-", 80))

	l.log(b.String())

	return nil
}

// loggerFromJSON builds a logger from JSON.
//
// Example JSON:
// {
//   "log.Logger": {
//     "scope": ["request", "response"],
//		 "headersOnly": true,
//		 "decode": true
//   }
// }
func loggerFromJSON(b []byte) (*parse.Result, error) {
	msg := &loggerJSON{}
	if err := json.Unmarshal(b, msg); err != nil {
		return nil, err
	}

	l := NewLogger()
	l.SetHeadersOnly(msg.HeadersOnly)
	l.SetDecode(msg.Decode)

	return parse.NewResult(l, msg.Scope)
}
