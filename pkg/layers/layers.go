package layers

import (
	"glint/ast"
	"glint/fastreq"
	"glint/logger"
	"glint/util"
	"reflect"
	"strings"

	"github.com/valyala/fasthttp"
)

type Plreq struct {
	Sess        *fastreq.Session
	Method      string
	Headers     map[string]string
	Body        []byte
	ContentType string
	Index       int
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

func (P *Plreq) RequestAll(originUrl string, paramValue string) ([]MFeatures, error) {
	var features []MFeatures
	origin, err := util.ParseUri(originUrl, P.Body, P.Method, P.ContentType)
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
	} else if strings.ToUpper(P.Method) == "GET" {
		for i, v := range originpayloads {
			req, resp, err := P.Sess.Get(v, P.Headers)
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

func (P *Plreq) RequestByIndex(idx int, originUrl string, paramValue string) (MFeatures, error) {
	var feature MFeatures
	origin, err := util.ParseUri(originUrl, P.Body, P.Method, P.ContentType)
	if err != nil {
		panic(err)
	}

	originpayload := origin.SetPayloadByindex(idx, originUrl, paramValue, P.Method)
	if strings.ToUpper(P.Method) == "POST" {

		req, resp, err := P.Sess.Post(originUrl, P.Headers, []byte(originpayload))
		if err != nil {
			logger.Error("Plreq request error: %v", err)
			return feature, err
		}

		feature.Index = idx
		feature.Request = req
		feature.Response = resp

	} else if strings.ToUpper(P.Method) == "GET" {

		req, resp, err := P.Sess.Get(originpayload, P.Headers)
		if err != nil {
			logger.Error("Plreq request error: %v", err)
			return feature, err
		}
		feature.Index = idx
		feature.Request = req
		feature.Response = resp
	}

	return feature, nil
}

//*[]MFeatures
func CompareFeatures(src *[]MFeatures, dst *[]MFeatures) bool {
	parse := ast.Parser{}
	var isEquivalent bool
	if len(*src) != len(*dst) {
		return false
	}
	isEquivalent = true

	for _, s := range *src {
		for _, d := range *dst {
			if s.Index == d.Index {
				parse.HttpParser(s.Response.String())
				s_tokens := parse.GetTokenizer()
				parse.HttpParser(d.Response.String())
				d_tokens := parse.GetTokenizer()
				if len(s_tokens) == 0 || len(d_tokens) == 0 {
					// logger.Error("SearchInputInResponse tokens 没有发现节点")
					return false
				}

				if len(s_tokens) != len(d_tokens) {
					// logger.Error("SearchInputInResponse tokens 没有发现节点")
					return false
				}

				// for _, st := range s_tokens {
				// 	for _, dt := range d_tokens {
				// 		if st.Idx == dt.Idx {
				// 			if st.Tagname != dt.Tagname {
				// 				isEquivalent = false
				// 			}
				// 		}
				// 	}
				// }
				if !reflect.DeepEqual(s_tokens, d_tokens) {
					isEquivalent = false
				}
			}
		}
	}
	return isEquivalent
}
