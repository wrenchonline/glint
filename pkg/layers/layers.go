package layers

import (
	"glint/fastreq"
	"glint/logger"
	"glint/util"
	"strings"

	"github.com/valyala/fasthttp"
)

type Plreq struct {
	Sess         *fastreq.Session
	Method       string
	Headers      map[string]string
	Body         []byte
	content_type string
}

type MFeatures struct {
	Index    int
	Request  *fasthttp.Request
	Response *fasthttp.Response
}

func (P *Plreq) Init(Proxy string, Cert string, PrivateKey string) {
	util.Setup()
	sess := fastreq.GetSessionByOptions(
		&fastreq.ReqOptions{
			Timeout:       5,
			AllowRedirect: true,
			Proxy:         Proxy,
			Cert:          Cert,
			PrivateKey:    PrivateKey,
		})
	P.Sess = sess
	P.Headers = make(map[string]string)
}

func (P *Plreq) Request(originUrl string, paramValue string) ([]MFeatures, error) {
	var features []MFeatures
	origin, err := util.ParseUri(originUrl, P.Body, P.Method, P.content_type)
	if err != nil {
		panic(err)
	}
	originpayloads := origin.SetPayload(originUrl, paramValue, P.Method)
	if strings.ToUpper(P.Method) == "POST" {
		for i, v := range originpayloads {
			req, resp, err := P.Sess.Post(originUrl, P.Headers, []byte(v))
			if err != nil {
				logger.Error("Plreq request error: %v", err)
				return nil, err
			}
			f := new(MFeatures)
			f.Index = i
			f.Request = req
			f.Response = resp
			features = append(features, *f)
		}
	}
	return features, nil
}
