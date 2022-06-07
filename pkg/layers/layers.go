package layers

import (
	"glint/ast"
	"glint/fastreq"
	"glint/logger"
	"glint/util"
	"strconv"
	"strings"
	"time"

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

type LastJob struct {
	Layer            Plreq
	Features         MFeatures
	ResponseDuration time.Duration
}

type MFeatures struct {
	Index    int
	Request  *fasthttp.Request
	Response *fasthttp.Response
}

func (P *LastJob) Init(Proxy string, Cert string, PrivateKey string) {
	util.Setup()
	sess := fastreq.GetSessionByOptions(
		&fastreq.ReqOptions{
			Timeout:       5 * time.Second,
			AllowRedirect: true,
			Proxy:         Proxy,
			Cert:          Cert,
			PrivateKey:    PrivateKey,
		})
	P.Layer.Sess = sess
	P.Layer.Headers = make(map[string]string)
}

func (P *LastJob) RequestAll(originUrl string, paramValue string) ([]MFeatures, error) {
	var features []MFeatures
	origin, err := util.ParseUri(originUrl, P.Layer.Body, P.Layer.Method, P.Layer.ContentType)
	if err != nil {
		logger.Error("Plreq request error: %v", err)
	}
	originpayloads := origin.SetPayload(originUrl, paramValue, P.Layer.Method)
	if strings.ToUpper(P.Layer.Method) == "POST" {
		for i, v := range originpayloads {
			req, resp, err := P.Layer.Sess.Post(originUrl, P.Layer.Headers, []byte(v))
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
	} else if strings.ToUpper(P.Layer.Method) == "GET" {
		for i, v := range originpayloads {
			req, resp, err := P.Layer.Sess.Get(v, P.Layer.Headers)
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

func (P *LastJob) RequestByIndex(idx int, originUrl string, paramValue string, o ...map[string]string) (MFeatures, error) {
	var feature MFeatures
	var Timeout int
	var err error
	for _, option := range o {
		if value, ok := option["timeout"]; ok {
			Timeout, err = strconv.Atoi(value)
			if err != nil {
				panic(err.Error())
			}
			P.Layer.Sess.Timeout = time.Duration(Timeout) * time.Second
		}
	}

	origin, err := util.ParseUri(originUrl, P.Layer.Body, P.Layer.Method, P.Layer.ContentType)
	if err != nil {
		panic(err)
	}

	originpayload := origin.SetPayloadByindex(idx, originUrl, paramValue, P.Layer.Method)

	if strings.ToUpper(P.Layer.Method) == "POST" {

		req, resp, err := P.Layer.Sess.Post(originUrl, P.Layer.Headers, []byte(originpayload))
		if err != nil {
			logger.Error("Plreq request error: %v", err)
			return feature, err
		}

		feature.Index = idx
		feature.Request = req
		feature.Response = resp
		P.Features = feature

	} else if strings.ToUpper(P.Layer.Method) == "GET" {

		req, resp, err := P.Layer.Sess.Get(originpayload, P.Layer.Headers)
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
				for i := 0; i < len(s_tokens); i++ {
					st := s_tokens[i]
					dt := d_tokens[i]
					if st.Tagname != dt.Tagname {
						isEquivalent = false
					} else {
						if st.Content != dt.Content {
							isEquivalent = false
						}
					}
				}
				// for _, st := range s_tokens {
				// 	for _, dt := range d_tokens {
				// 		if st.Idx == dt.Idx {
				// 			if st.Tagname != dt.Tagname {
				// 				isEquivalent = false
				// 			} else {
				// 				if st.Content != dt.Content {
				// 					isEquivalent = false
				// 				}
				// 			}
				// 		}
				// 	}
				// }
				// if !reflect.DeepEqual(s_tokens, d_tokens) {
				// 	isEquivalent = false
				// }
			}
		}
	}
	return isEquivalent
}
