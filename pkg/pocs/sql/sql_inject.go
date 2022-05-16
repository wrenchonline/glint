package sql

import (
	"glint/fastreq"
	"glint/logger"
	"math"
	"math/rand"
	"regexp"
	"time"

	"github.com/valyala/fasthttp"
)

//此页面处理sql盲注

var letterFrequency = [...]int{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 49, 71, 49, 0, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 116, 30, 64, 60, 218, 24, 34, 72, 105, 5, 16, 68, 56, 101, 127, 46, 0, 110, 123, 139, 57, 19, 44, 4, 35, 1, 0, 0, 0, 0, 0,
}

var DefaultProxy = ""
var cert string
var mkey string

const partitionOptimization = 2
const challenge = "haribol"

var poeRequests = 0

var DBMSList = []string{
	"MYSQL", "MSSQL", "POSTGRESQL", "ORACLE", "RAILS",
}
var prioDBMS = 0

var Counter = 0

var SQLI_CONSTS map[string]int

// Set up DBMS "constants"
func setDBMSConst() {
	SQLI_CONSTS = make(map[string]int)
	for _, v := range DBMSList {
		SQLI_CONSTS[v] = int(math.Pow(3, float64(Counter)))
		Counter++
	}
}

func getGlobelValue(key string) interface{} {
	return nil
}

//计算优先级
func calcDMBSPriorities() int {
	var val = 0
	for _, v := range DBMSList {
		b := getGlobelValue("sqli." + v)
		if b.(bool) {
			val += SQLI_CONSTS[v]
		}
	}
	return val
}

type classBlindSQLInj struct {
	scheme                  string
	inputIndex              int
	variations              []string
	foundVulnOnVariation    bool
	scanningAnInternalIP    bool
	scanningATestWebsite    bool
	longDuration            int
	shortDuration           int
	isNumeric               bool
	isBase64                bool
	responseIsStable        bool
	origValue               string
	confirmInjectionHistory []string
	lastJob                 LastJob
	origBody                interface{}
	origFeatures            string //原始特征
	lastJobProof            interface{}
	proofExploitTemplate    string
	proofExploitVarIndex    int
	trueFeatures            interface{}
	originalFullResponse    bool
	disableSensorBased      bool
	sess                    *fastreq.Session
	method                  string
}

type LastJob struct {
	request          *fasthttp.Request
	response         *fasthttp.Response
	responseDuration time.Duration
}

func (bsql *classBlindSQLInj) Init() {
	sess := fastreq.GetSessionByOptions(
		&fastreq.ReqOptions{
			Timeout:       5,
			AllowRedirect: true,
			Proxy:         DefaultProxy,
			Cert:          cert,
			PrivateKey:    mkey,
		})
	bsql.sess = sess
}

func (bsql *classBlindSQLInj) filterBody(body string, testValue string) string {
	reg1 := regexp.MustCompile(`([0-1]?[0-9]|[2][0-3]):([0-5][0-9])[.|:]([0-9][0-9])`)
	body1 := reg1.ReplaceAllString(body, "")
	reg2 := regexp.MustCompile(`time\s*[:]\s*\d+\.?\d*`)
	body2 := reg2.ReplaceAllString(body1, "")
	// if testValue is provided it needs to be removed from the response
	// if testValue != "" {
	// 	str := strings.Replace(body, testValue, "")
	// }

	return body2
}

func (bsql *classBlindSQLInj) checkIfResponseIsStable(varIndex interface{}) bool {
	var Time1 time.Duration
	var Time2 time.Duration
	// send original value
	body1 := bsql.filterBody(bsql.lastJob.response.String(), bsql.origValue)
	bsql.origBody = body1
	bsql.origFeatures = bsql.lastJob.response.String()
	Time1 = bsql.lastJob.responseDuration
	// send same value (to see if the response is different)
	var body2 string

	return false

}

func (bsql *classBlindSQLInj) confirmInjectionWithOR(varIndex interface{}, quoteChar string, confirmed bool, dontCommentRestOfQuery bool) {
	// original value
	bsql.origValue = "-1"
	origValue := bsql.origValue
	randNum := rand.Intn(1000)
	paramValue := bsql.origValue
	randString := string(randNum)
	if confirmed {
		randString = `000` + randString
	}
	// equalitySign := "="
	// test TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 2+" + randString + "-" + randString + "-1=0+0+0+1 -- "
	if dontCommentRestOfQuery {
		paramValue = paramValue[:len(paramValue)-4]
	}
	logger.Debug("paramValue:%s", paramValue)

	bsql.sess.Request(bsql.method)
}
