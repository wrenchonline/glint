package proxy

import (
	"glint/util"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/martian/log"
	"github.com/google/martian/proxyutil"
	"github.com/google/martian/v3"
	"github.com/google/martian/v3/messageview"
)

// PassiveProxy
type PassiveProxy struct {
	bodyLogging     func(*http.Response) bool
	postDataLogging func(*http.Request) bool
	mu              sync.Mutex
	taskid          int //发送到特定任务去扫描
}

func NewPassiveProxy() *PassiveProxy {
	p := &PassiveProxy{}
	return p
}

// ModifyRequest 过滤请求消息，跟据从请求发送消息
func (p *PassiveProxy) ModifyRequest(req *http.Request) error {
	ctx := martian.NewContext(req)
	if ctx.SkippingLogging() {
		return nil
	}

	id := ctx.ID()

	return p.RecordRequest(id, req)
}

func postData(req *http.Request, logBody bool) (*util.PostData, error) {
	// If the request has no body (no Content-Length and Transfer-Encoding isn't
	// chunked), skip the post data.
	if req.ContentLength <= 0 && len(req.TransferEncoding) == 0 {
		return nil, nil
	}

	ct := req.Header.Get("Content-Type")
	mt, ps, err := mime.ParseMediaType(ct)
	if err != nil {
		log.Errorf("har: cannot parse Content-Type header %q: %v", ct, err)
		mt = ct
	}

	pd := &util.PostData{
		MimeType: mt,
		Params:   []util.Param{},
	}

	if !logBody {
		return pd, nil
	}

	mv := messageview.New()
	if err := mv.SnapshotRequest(req); err != nil {
		return nil, err
	}

	br, err := mv.BodyReader()
	if err != nil {
		return nil, err
	}

	switch mt {
	case "multipart/form-data":
		mpr := multipart.NewReader(br, ps["boundary"])

		for {
			p, err := mpr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			defer p.Close()

			body, err := ioutil.ReadAll(p)
			if err != nil {
				return nil, err
			}

			pd.Params = append(pd.Params, util.Param{
				Name:        p.FormName(),
				Filename:    p.FileName(),
				ContentType: p.Header.Get("Content-Type"),
				Value:       string(body),
			})
		}
	case "application/x-www-form-urlencoded":
		body, err := ioutil.ReadAll(br)
		if err != nil {
			return nil, err
		}

		vs, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}

		for n, vs := range vs {
			for _, v := range vs {
				pd.Params = append(pd.Params, util.Param{
					Name:  n,
					Value: v,
				})
			}
		}
	default:
		body, err := ioutil.ReadAll(br)
		if err != nil {
			return nil, err
		}

		pd.Text = string(body)
	}

	return pd, nil
}

func headers(hs http.Header) []util.Header {
	hhs := make([]util.Header, 0, len(hs))

	for n, vs := range hs {
		for _, v := range vs {
			hhs = append(hhs, util.Header{
				Name:  n,
				Value: v,
			})
		}
	}

	return hhs
}

func cookies(cs []*http.Cookie) []util.Cookie {
	hcs := make([]util.Cookie, 0, len(cs))

	for _, c := range cs {
		var expires string
		if !c.Expires.IsZero() {
			expires = c.Expires.Format(time.RFC3339)
		}

		hcs = append(hcs, util.Cookie{
			Name:        c.Name,
			Value:       c.Value,
			Path:        c.Path,
			Domain:      c.Domain,
			HTTPOnly:    c.HttpOnly,
			Secure:      c.Secure,
			Expires:     c.Expires,
			Expires8601: expires,
		})
	}

	return hcs
}

// NewRequest constructs and returns a Request from req. If withBody is true,
// req.Body is read to EOF and replaced with a copy in a bytes.Buffer. An error
// is returned (and req.Body may be in an intermediate state) if an error is
// returned from req.Body.Read.
func NewRequest(req *http.Request, withBody bool) (*util.Request, error) {

	r := &util.Request{
		Method:      req.Method,
		URL:         req.URL.String(),
		HTTPVersion: req.Proto,
		HeadersSize: -1,
		BodySize:    req.ContentLength,
		QueryString: []util.QueryString{},
		Headers:     headers(proxyutil.RequestHeader(req).Map()),
		Cookies:     cookies(req.Cookies()),
	}

	for n, vs := range req.URL.Query() {
		for _, v := range vs {
			r.QueryString = append(r.QueryString, util.QueryString{
				Name:  n,
				Value: v,
			})
		}
	}

	pd, err := postData(req, withBody)
	if err != nil {
		return nil, err
	}
	r.PostData = pd

	return r, nil
}

// RecordRequest logs the HTTP request with the given ID. The ID should be unique
// per request/response pair.
func (p *PassiveProxy) RecordRequest(id string, req *http.Request) error {
	hreq, err := NewRequest(req, p.postDataLogging(req))
	if err != nil {
		return err
	}
	headers, err := util.ConvertHeaders(hreq.Headers)
	if err != nil {
		return err
	}
	url := hreq.URL

	postdata := []byte(hreq.PostData.Text)

	//contenttype := hreq.PostData.MimeType

	method := hreq.Method

	ReqList := make(map[string][]interface{})

	element := make(map[string]interface{})
	element["url"] = url
	element["method"] = method
	element["headers"] = headers
	element["data"] = postdata
	element["source"] = "agent"
	ReqList["agent"] = append(ReqList["agent"], element)

	return nil
}
