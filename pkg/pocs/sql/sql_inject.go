package sql

import (
	"encoding/json"
	"glint/fastreq"
	"glint/logger"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"math"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/thoas/go-funk"
)

//此页面处理sql盲注

var letterFrequency = [...]int{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 49, 71, 49, 0, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 116, 30, 64, 60, 218, 24, 34, 72, 105, 5, 16, 68, 56, 101, 127, 46, 0, 110, 123, 139, 57, 19, 44, 4, 35, 1, 0, 0, 0, 0, 0,
}

var DefaultProxy = "127.0.0.1:7777"
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

type TimeoutResult struct {
	Value  string
	Output string
}

type classBlindSQLInj struct {
	scheme                        string
	TargetUrl                     string
	inputIndex                    int
	variations                    *util.PostData
	foundVulnOnVariation          bool
	scanningAnInternalIP          bool
	scanningATestWebsite          bool
	longDuration                  float64
	shortDuration                 float64
	isNumeric                     bool
	isBase64                      bool
	responseIsStable              bool
	origValue                     string
	confirmInjectionHistory       []InjectionResult
	ConfirmInjectionHistoryTiming []TimeoutResult
	lastJob                       layers.LastJob
	origBody                      interface{}
	origFeatures                  layers.MFeatures //原始特征
	lastJobProof                  interface{}
	proofExploitTemplate          string
	proofExploitVarIndex          int
	proofExploitExploitType       int
	trueFeatures                  layers.MFeatures
	originalFullResponse          bool
	disableSensorBased            bool
	origStatusCode                int
	responseTimingIsStable        bool
	inputIsStable                 bool
	// sess                    *fastreq.Session
	// method                  string
}

// type LastJob struct {
// 	layer            layers.Plreq
// 	Features         layers.MFeatures
// 	responseDuration time.Duration
// }

func (bsql *classBlindSQLInj) Init() {

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
	Feature, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, bsql.origValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	Time1 = time.Since(s)
	//发送目标值
	body1 := bsql.filterBody(Feature.Response.String(), bsql.origValue)
	body1Features := Feature
	bsql.origBody = body1
	bsql.origFeatures = Feature
	bsql.lastJob.ResponseDuration = Time1
	bsql.longDuration = 8
	bsql.shortDuration = 5

	// 发送一些值 (查看回复是否不同)
	// bsql.origMessage = bsql.Response.msg3
	bsql.origStatusCode = Feature.Response.StatusCode()
	s2 := time.Now()
	Feature2, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, bsql.origValue)
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

	if !layers.CompareFeatures(&[]layers.MFeatures{Feature}, &[]layers.MFeatures{Feature2}) {
		logger.Debug("body1:%s", body1)
		logger.Debug("body2:%s", body2)
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
	Feature3, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, newValue)
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
		!layers.CompareFeatures(&[]layers.MFeatures{body1Features}, &[]layers.MFeatures{body3Features}) {
		bsql.inputIsStable = true
		logger.Debug("input is stable. good")
	} else {
		bsql.inputIsStable = false
	}

	return true

}

func (bsql *classBlindSQLInj) addToConfirmInjectionHistory(Value string, result bool) {
	bsql.confirmInjectionHistory = append(bsql.confirmInjectionHistory, InjectionResult{Value: Value, Result: result})
}

func (bsql *classBlindSQLInj) addToConfirmInjectionHistoryTiming(Value string, result string) {
	bsql.ConfirmInjectionHistoryTiming = append(bsql.ConfirmInjectionHistoryTiming, TimeoutResult{Value: Value, Output: result})
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

	testbody, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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

	testbody1, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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

	testbody2, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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

	testbody3, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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

	testbody4, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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

	testbody5, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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

	testbody6, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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

	testbody7, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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

	testbody8, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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

	testbody9, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
		randString = strconv.Itoa(randNum)
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
		testbody, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if !layers.CompareFeatures(&[]layers.MFeatures{testbody}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed Number test 1")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, true)
		// test 2 FALSE  -------------------------------------------------------------
		paramValue = origValue + "*" + strconv.Itoa(randNum) + "*" + strconv.Itoa(randNum-5) + "*0"
		logger.Debug("%s", paramValue)
		testbody1, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if layers.CompareFeatures(&[]layers.MFeatures{testbody1}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed Number test 2")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, false)
		// test 3 TRUE  -------------------------------------------------------------
		paramValue = "(" + strconv.Itoa((origValueAsInt + (randNum + 5))) + "-" + strconv.Itoa(randNum) + "-5)"
		logger.Debug("%s", paramValue)
		testbody2, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if !layers.CompareFeatures(&[]layers.MFeatures{testbody2}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed Number test 3")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, true)
		// test 4 TRUE  -------------------------------------------------------------
		paramValue = strconv.Itoa(origValueAsInt) + "/1"
		logger.Debug("%s", paramValue)
		testbody3, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if !layers.CompareFeatures(&[]layers.MFeatures{testbody3}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed Number test 4")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, true)
		// test 5 FALSE  -------------------------------------------------------------
		paramValue = strconv.Itoa(origValueAsInt) + "/0"
		logger.Debug("%s", paramValue)
		testbody4, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		if layers.CompareFeatures(&[]layers.MFeatures{testbody4}, &[]layers.MFeatures{origFeatures}) {
			logger.Debug("failed Number test 5")
			return false
		}
		bsql.addToConfirmInjectionHistory(paramValue, false)
		// test 6 TRUE  -------------------------------------------------------------
		paramValue = strconv.Itoa(origValueAsInt) + "/(3*2-5)"
		logger.Debug("%s", paramValue)
		testbody5, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
		testbody, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
		testbody1, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
		testbody2, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
		testbody3, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
		testbody4, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
		testbody5, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
	randString := strconv.Itoa(randNum)
	origFeatures := bsql.origFeatures
	if confirmed {
		randString = `000` + randString
	}
	// test 1 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " RLIKE (SELECT (CASE WHEN (" +
		randString + "=" + randString + ") THEN 1 ELSE 0x28 END)) -- "
	logger.Debug("%s", paramValue)
	testBody, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
	testBody2, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
	testBody3, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
	testBody4, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
	testBody5, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
	testBody6, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
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
	randString := strconv.Itoa(randnum)
	origFeatures := bsql.origFeatures
	if confirmed {
		randString = `000` + randString
	}
	randStrLong := util.RandStr(8)

	randNum := strconv.Itoa(randnum)
	// equalitySign := "="
	// test 1 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 2+" + randNum + "-" + randNum +
		"-1=0+0+0+1 or " + quoteChar + randStrLong + quoteChar + "=" + quoteChar
	logger.Debug("%s", paramValue)
	testBody, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed Like test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)
	trueBody := testBody

	//test 2 FALSE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3+" + randNum + "-" + randNum + "-1=0+0+0+1 or " +
		quoteChar + randStrLong + quoteChar + "=" + quoteChar
	logger.Debug("%s", paramValue)
	testBody2, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody2}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	//test 3 FALSE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2<(0+5+" + randNum + "-" + randNum +
		") or " + quoteChar + randStrLong + quoteChar + "=" + quoteChar
	logger.Debug("%s", paramValue)
	testBody3, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody3}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)
	//test 4 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2>(0+5+" + randNum + "-" + randNum + ") or " +
		quoteChar + randStrLong + quoteChar + "=" + quoteChar
	logger.Debug("%s", paramValue)
	testBody4, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody4}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	//test 5 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 2+1-1-1=1 AND " + randString + "=" + randString +
		" or " + quoteChar + randStrLong + quoteChar + "=" + quoteChar
	logger.Debug("%s", paramValue)
	testBody5, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	trueBody = testBody5
	//test 6 FALSE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 2+1-1+1=1 AND " + randString + "=" +
		randString + " or " + quoteChar + randStrLong + quoteChar + "=" + quoteChar
	logger.Debug("%s", paramValue)
	testBody6, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody6}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)
	//test 7 FALSE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2=5 AND " + randString + "=" + randString +
		" or " + quoteChar + randStrLong + quoteChar + "=" + quoteChar

	logger.Debug("%s", paramValue)
	testBody7, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody7}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	//test 8 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2=6 AND " + randString + "=" + randString +
		" or " + quoteChar + randStrLong + quoteChar + "=" + quoteChar

	logger.Debug("%s", paramValue)
	testBody8, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody8}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	//test 9 FALSE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2=6 AND " + randString + "=" + randString +
		" or " + quoteChar + randStrLong + quoteChar + "=" + quoteChar

	logger.Debug("%s", paramValue)
	testBody9, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody9}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)
	//test 10 TRUE  -------------------------------------------------------------
	paramValue = origValue + quoteChar + " OR 3*2=6 AND " + randString + "=" + randString +
		" or " + quoteChar + randStrLong + quoteChar + "=" + quoteChar

	logger.Debug("%s", paramValue)
	testBody10, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody10}, &[]layers.MFeatures{trueBody}) {
		logger.Debug("failed Like test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	// save a template payload for proof of exploit
	bsql.proofExploitTemplate = origValue + quoteChar + " OR {query} AND " + randString + "=" + randString + " or " + quoteChar + randStrLong + quoteChar + "=" + quoteChar
	// if dontCommentRestOfQuery {
	// 	bsql.proofExploitTemplate = bsql.proofExploitTemplate[:len(bsql.proofExploitTemplate)-4]
	// }
	bsql.proofExploitVarIndex = varIndex
	bsql.proofExploitExploitType = 0 //0=boolean, 1=timing
	bsql.trueFeatures = trueBody

	return true
}

func (bsql *classBlindSQLInj) confirmInjectionOrderBy(varIndex int, confirmed bool) bool {
	bsql.origValue = "-1"
	// origValue := bsql.origValue
	randnum := rand.Intn(1000)
	paramValue := bsql.origValue
	randString := strconv.Itoa(randnum)
	// origFeatures := bsql.origFeatures
	if confirmed {
		randString = `000` + randString
	}
	// randStrLong := util.RandStr(8)

	// randNum := string(rune(randnum))

	equalitySign := "="

	baseline := "1,(select case when (${comparison}) then 1 else 1*(select table_name from information_schema.tables)end)=1"
	// BASELINE  -------------------------------------------------------------
	paramValue = strings.Replace(baseline, "${comparison}", randString+equalitySign+randString, 1)
	//paramValue = baseline.replace("${comparison}", randString+equalitySign+randString)
	logger.Debug("%s", paramValue)
	origBody, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	// test 1 TRUE  -------------------------------------------------------------
	paramValue = strings.Replace(baseline, "${comparison}", "2+1-1-1=0+0+0+1", 1)
	logger.Debug("%s", paramValue)
	testBody, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody}, &[]layers.MFeatures{origBody}) {
		logger.Debug("failed string test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	// test 2 FALSE	  -------------------------------------------------------------
	paramValue = strings.Replace(baseline, "${comparison}", "3+1-1-1=0+0+0+1", 1)
	logger.Debug("%s", paramValue)
	testBody2, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody2}, &[]layers.MFeatures{origBody}) {
		logger.Debug("failed string test 2")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	// test 3 FALSE	  -------------------------------------------------------------
	paramValue = strings.Replace(baseline, "${comparison}", "3+1-1-1=0+0+0+1", 1)
	logger.Debug("%s", paramValue)
	testBody3, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody3}, &[]layers.MFeatures{origBody}) {
		logger.Debug("failed string test 3")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	// test 4 TRUE	  -------------------------------------------------------------
	paramValue = strings.Replace(baseline, "${comparison}", "3*2>(0+5+0+0)", 1)
	logger.Debug("%s", paramValue)
	testBody4, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody4}, &[]layers.MFeatures{origBody}) {
		logger.Debug("failed string test 4")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	// test 5 TRUE	  -------------------------------------------------------------
	paramValue = strings.Replace(baseline, "${comparison}", "3*2>(0+5+0+0)", 1)
	logger.Debug("%s", paramValue)
	testBody5, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody5}, &[]layers.MFeatures{origBody}) {
		logger.Debug("failed common test 5")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)
	// test 6 FALSE	  -------------------------------------------------------------
	paramValue = strings.Replace(baseline, "${comparison}", "3+1-1-1=1)", 1)
	logger.Debug("%s", paramValue)
	testBody6, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody6}, &[]layers.MFeatures{origBody}) {
		logger.Debug("failed common test 6")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)
	// test 7 FALSE	  -------------------------------------------------------------
	paramValue = strings.Replace(baseline, "${comparison}", "3*2=5 AND "+randString+equalitySign+randString, 1)
	logger.Debug("%s", paramValue)
	testBody7, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody7}, &[]layers.MFeatures{origBody}) {
		logger.Debug("failed common test 7")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	// test 8 TRUE	  -------------------------------------------------------------
	paramValue = strings.Replace(baseline, "${comparison}", "3*2=6 AND "+randString+equalitySign+randString, 1)
	logger.Debug("%s", paramValue)
	testBody8, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody8}, &[]layers.MFeatures{origBody}) {
		logger.Debug("failed common test 8")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	// test 9 False	  -------------------------------------------------------------
	paramValue = strings.Replace(baseline, "${comparison}", "3*2*0=6 AND "+randString+equalitySign+randString, 1)
	logger.Debug("%s", paramValue)
	testBody9, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody9}, &[]layers.MFeatures{origBody}) {
		logger.Debug("failed common test 9")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	// test 10 true	  -------------------------------------------------------------
	paramValue = strings.Replace(baseline, "${comparison}", "3*2*1=6 AND "+randString+equalitySign+randString, 1)
	logger.Debug("%s", paramValue)
	testBody10, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody10}, &[]layers.MFeatures{origBody}) {
		logger.Debug("failed common test 10")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	return true
}

/*****************************************************************/
/* timing tests */
/*****************************************************************/
func (bsql *classBlindSQLInj) genSleepString(sleepType string) string {
	switch sleepType {
	case "long":
		return strconv.FormatFloat(bsql.longDuration, 'f', 0, 64)
	case "verylong":
		return "15"
	case "mid":
		return strconv.FormatFloat(bsql.shortDuration, 'f', 0, 64)
	case "2xmid":
		return strconv.FormatFloat(bsql.shortDuration*2+1, 'f', 0, 64)
	case "none":
		return "0"
	}
	return ""
}

func (bsql *classBlindSQLInj) genBenchmarkSleepString(sleepType string) string {
	switch sleepType {
	case "long":
		return "70000000"
	case "verylong":
		return "110000000"
	case "mid":
		return "50000000"
	case "2xmid":
		return "50000000"
	case "none":
		return "0"
	}
	return ""
}

func (bsql *classBlindSQLInj) testTiming(varIndex int, paramValue string, dontEncode bool) bool {
	// load scheme variation
	origParamValue := paramValue
	// var confirmed = false
	var Time1 = 0. // long
	var Time2 = 0. // no
	var Time3 = 0. // mid
	var Time4 = 0. // very long

	var timeOutSecs = 20
	var zeroTimeOut = bsql.shortDuration - 1
	if zeroTimeOut > 3 {
		zeroTimeOut = 3
	}
	var timeOutCounter = 0

	var tempParamValue = strings.ReplaceAll(paramValue, "{ORIGVALUE}", bsql.origValue)
	tempParamValue = strings.ReplaceAll(paramValue, "{RANDSTR}", util.RandStr(8))
	tempParamValue = strings.ReplaceAll(paramValue, "{RANDNUMBER}", string(rand.Intn(1000)))
	// prepare proof of exploit / confirmation template
	bsql.proofExploitTemplate = tempParamValue
	bsql.proofExploitVarIndex = varIndex
	bsql.proofExploitExploitType = 1 // 0=boolean, 1=timing

	stepLongDelay := func() bool {
		paramValue = strings.ReplaceAll(origParamValue, "{SLEEP}", bsql.genSleepString("long"))
		paramValue = strings.ReplaceAll(paramValue, "{ORIGVALUE}", bsql.origValue)
		paramValue = strings.ReplaceAll(paramValue, "{RANDSTR}", util.RandStr(8))
		paramValue = strings.ReplaceAll(paramValue, "{RANDNUMBER}", string(rand.Intn(1000)))
		logger.Debug("paramValue:%s", paramValue)
		timeout := make(map[string]string)
		timeout["timeout"] = string(timeOutSecs)
		_, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue, timeout)
		if err != nil {
			logger.Error("%s", err.Error())
			return false
		}
		Time1 = float64(bsql.lastJob.ResponseDuration.Seconds())
		bsql.addToConfirmInjectionHistoryTiming(paramValue, string(int(Time1)))
		logger.Debug("Time1:", Time1)
		if Time1 < bsql.longDuration*99/100 {
			return false
		}
		return true
	}

	stepZeroDelay := func() bool {
		paramValue = strings.ReplaceAll(origParamValue, "{SLEEP}", bsql.genSleepString("none"))
		paramValue = strings.ReplaceAll(paramValue, "{ORIGVALUE}", bsql.origValue)
		paramValue = strings.ReplaceAll(paramValue, "{RANDSTR}", util.RandStr(8))
		paramValue = strings.ReplaceAll(paramValue, "{RANDNUMBER}", string(rand.Intn(1000)))
		logger.Debug("paramValue:%s", paramValue)
		timeout := make(map[string]string)
		timeout["timeout"] = string(timeOutSecs)
		_, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue, timeout)
		if err != nil {
			logger.Error("%s", err.Error())
			return false
		}
		Time2 = float64(bsql.lastJob.ResponseDuration.Seconds())
		bsql.addToConfirmInjectionHistoryTiming(paramValue, string(int(Time2)))
		logger.Debug("Time2:", Time2)
		if Time2 > zeroTimeOut {
			return false
		}
		return true
	}

	stepMidDelay := func() bool {
		paramValue = strings.ReplaceAll(origParamValue, "{SLEEP}", bsql.genSleepString("mid"))
		paramValue = strings.ReplaceAll(paramValue, "{ORIGVALUE}", bsql.origValue)
		paramValue = strings.ReplaceAll(paramValue, "{RANDSTR}", util.RandStr(8))
		paramValue = strings.ReplaceAll(paramValue, "{RANDNUMBER}", string(rand.Intn(1000)))
		logger.Debug("paramValue:%s", paramValue)
		timeout := make(map[string]string)
		timeout["timeout"] = string(timeOutSecs)
		_, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue, timeout)
		if err != nil {
			logger.Error("%s", err.Error())
			return false
		}
		Time3 = float64(bsql.lastJob.ResponseDuration.Seconds())
		bsql.addToConfirmInjectionHistoryTiming(paramValue, string(int(Time3)))
		logger.Debug("Time3:", Time3)
		if Time3 < bsql.longDuration*99/100 {
			return false
		}
		return true
	}

	stepVeryLongDelay := func() bool {
		var veryLongDuration = 15.
		paramValue = strings.ReplaceAll(origParamValue, "{SLEEP}", bsql.genSleepString("verylong"))
		paramValue = strings.ReplaceAll(paramValue, "{ORIGVALUE}", bsql.origValue)
		paramValue = strings.ReplaceAll(paramValue, "{RANDSTR}", util.RandStr(8))
		paramValue = strings.ReplaceAll(paramValue, "{RANDNUMBER}", string(rand.Intn(1000)))
		logger.Debug("paramValue:%s", paramValue)
		timeout := make(map[string]string)
		timeout["timeout"] = string(timeOutSecs)
		_, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue, timeout)

		Time4 = float64(bsql.lastJob.ResponseDuration.Seconds())
		bsql.addToConfirmInjectionHistoryTiming(paramValue, string(int(Time4)))
		logger.Debug("Time4:", Time4)
		if err != nil {
			// logger.Error("%s", err.Error())
			return true
		}
		if Time4 < veryLongDuration*99/100 {
			return false
		}
		return true
	}

	var permutations = []string{
		"lzvm", "lzmv", "lvzm", "lvmz",
		"lmzv", "lmvz", "vzlm", "vzml",
		"vlzm", "vlmz", "vmzl", "vmlz",
		"mzlv", "mzvl", "mlzv", "mlvz",
		"mvzl", "mvlz",
	}

	//因为执行sql超时插件时候有众多其他插件也在执行，这会影响目标服务器收发包的时间。
	//所以它定制一个策略，就是身处在某种环境下执行函数的序列指定策略
	//因为我的插件没有这种结构我才去第一种方案
	var permutation = "v" + permutations[0] + "zlz"

	for _, v := range permutation {
		switch v {
		case 'z':
			if !stepZeroDelay() {
				return false
			}
		case 'l':
			if !stepLongDelay() {
				return false
			}
		case 'v':
			if !stepVeryLongDelay() {
				return false
			}
		case 'm':
			if !stepMidDelay() {
				return false
			}
		}
	}
	/*
	   var Time1 => // long  		(4)
	   var Time2 => // no 			(0)
	   var Time3 => // mid 		(3)
	   var Time4 => // very long 	(6)
	*/
	if Time3 > Time4 || Time3 > Time1 || Time2 > Time4 || Time2 > Time1 {
		return false
	}
	if Time3 >= Time1 {
		return false
	}

	if Time1 >= Time4 {
		return false
	}

	if timeOutCounter >= 0 {
		return false
	}

	return true
}

func isEven(n int) bool {
	return n%2 == 0
}

func (bsql *classBlindSQLInj) responseIsInternalServerError() bool {
	body := strings.ToLower(bsql.lastJob.Features.Response.String())
	if funk.Contains(body, "error") {
		return true
	}
	if bsql.lastJob.Features.Response.StatusCode() == 500 {
		return true
	}
	return false
}

func (bsql *classBlindSQLInj) confirmInjectionWithOddEvenNumbers(varIndex int, confirmed bool) bool {
	logger.Debug("confirmInjectionWithOddEvenNumbers %d , %v", varIndex, confirmed)
	var paramValue string
	// var origValue = "1"
	var maxRounds = 7

	for i := 0; i < maxRounds; i++ {
		randnum := rand.Intn(1000)
		randNum := strconv.Itoa(randnum)
		if confirmed {
			paramValue = randNum + strings.Repeat("*1", i)
		} else {
			paramValue = randNum + strings.Repeat("-0", i)
		}

		if !isEven(i) {
			//如果奇数，删除最后一个0
			paramValue = paramValue[:len(paramValue)-1]
		}

		logger.Debug("paramValue %s", paramValue)
		testBody7, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		bsql.lastJob.Features = testBody7
		if isEven(i) {
			// even 2, 4, 6
			if bsql.responseIsInternalServerError() {
				logger.Debug("failed OddEven test (OK expected)  %d", i)
				return false
			}
		} else {
			// odd 1, 3, 5
			if !bsql.responseIsInternalServerError() {
				logger.Debug("failed OddEven test (ERROR expected)  %d", i)
				return false
			}
		}
		bsql.addToConfirmInjectionHistory(paramValue, bsql.responseIsInternalServerError())
	}

	return true
}

func (bsql *classBlindSQLInj) confirmInjectionWithOddEvenStrings(varIndex int, confirmed bool) bool {
	logger.Debug("confirmInjectionWithOddStrings %d , %v", varIndex, confirmed)
	// var origValue = "1"
	var maxRounds = 7
	var paramValue string

	for i := 0; i < maxRounds; i++ {
		randnum := rand.Intn(1000)
		randNum := strconv.Itoa(randnum)
		if confirmed {
			randNum = util.RandStr(6)
		}
		paramValue = randNum + strings.Repeat("'", i)
		logger.Debug("paramValue %s", paramValue)
		testBody7, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
		if err != nil {
			logger.Error("%s", err.Error())
		}
		bsql.lastJob.Features = testBody7
		if isEven(i) {
			// even 2, 4, 6
			if bsql.responseIsInternalServerError() {
				logger.Debug("failed OddEven test (OK expected)  %d", i)
				return false
			}
		} else {
			// odd 1, 3, 5
			if !bsql.responseIsInternalServerError() {
				logger.Debug("failed OddEven test (ERROR expected)  %d", i)
				return false
			}
		}
		bsql.addToConfirmInjectionHistory(paramValue, bsql.responseIsInternalServerError())
	}

	return true
}

func (bsql *classBlindSQLInj) confirmInjectionWithOddEven(varIndex int, confirmed bool) bool {
	logger.Debug("confirmInjectionWithOddStrings %d , %v", varIndex, confirmed)
	randnum := rand.Intn(1000)
	randNum := strconv.Itoa(randnum)
	// [1]. test with a single quote -------------------------------------------------
	var paramValue = randNum + "'"
	logger.Debug("paramValue %s", paramValue)
	feature, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	bsql.lastJob.Features = feature
	if !bsql.responseIsInternalServerError() {
		logger.Debug("failed OddEven test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, bsql.responseIsInternalServerError())

	// [2]. test with two single quotes ------------------------------------------------
	paramValue = randNum + "''"
	logger.Debug("paramValue %s", paramValue)
	feature1, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	bsql.lastJob.Features = feature1

	bsql.addToConfirmInjectionHistory(paramValue, bsql.responseIsInternalServerError())
	// if error, it could be a number injection
	if bsql.responseIsInternalServerError() {
		bsql.confirmInjectionWithOddEvenNumbers(varIndex, confirmed)
	} else {
		bsql.confirmInjectionWithOddEvenStrings(varIndex, confirmed)
	}

	return true
}

func (bsql *classBlindSQLInj) confirmInjectionStringConcatenation(varIndex int, confirmed bool) bool {
	logger.Debug("confirmInjectionStringConcatenation %d , %v", varIndex, confirmed)
	//bsql.origValue = "-1"
	origValue := bsql.origValue
	randnum := rand.Intn(1000)
	paramValue := bsql.origValue
	randString := strconv.Itoa(randnum)

	origFeatures := bsql.origFeatures
	if confirmed {
		randString = `000` + randString
	}

	// test 1 TRUE  -------------------------------------------------------------
	paramValue = origValue + "'||'"
	logger.Debug("%s", paramValue)
	testBody, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())
	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed concat test 1")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	// test 2 FALSE  -------------------------------------------------------------
	paramValue = origValue + "'|||'"
	logger.Debug("%s", paramValue)
	testBody2, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())

	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody2}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed concat test 2")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	// test 3 TRUE  -------------------------------------------------------------
	paramValue = origValue + "'||''||'"
	logger.Debug("%s", paramValue)
	testBody3, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())

	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody3}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed concat test 3")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	// test 4 FALSE   -------------------------------------------------------------
	paramValue = origValue + "'||'" + randString + "'||'"
	logger.Debug("%s", paramValue)
	testBody4, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())

	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody4}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed concat test 4")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	// test 5 TRUE   -------------------------------------------------------------
	paramValue = "'||''||'" + origValue
	logger.Debug("%s", paramValue)
	testBody5, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())

	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody5}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed concat test 5")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	// test 6 FALSE   -------------------------------------------------------------
	paramValue = "'||''||'" + origValue
	logger.Debug("%s", paramValue)
	testBody6, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())

	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody6}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed concat test 6")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	// test 7 FALSE   -------------------------------------------------------------
	paramValue = "'||''||'" + origValue
	logger.Debug("%s", paramValue)
	testBody7, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())

	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody7}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed concat test 7")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	//test 8 TRUE   -------------------------------------------------------------
	paramValue = origValue[:1] + "'||'" + origValue[1:]
	logger.Debug("%s", paramValue)
	testBody8, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())

	}
	if !layers.CompareFeatures(&[]layers.MFeatures{testBody8}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed concat test 8")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, true)

	//test 9 FALSE   -------------------------------------------------------------
	paramValue = origValue[:1] + "'|a|'" + origValue[1:]
	logger.Debug("%s", paramValue)
	testBody9, err := bsql.lastJob.RequestByIndex(varIndex, bsql.TargetUrl, paramValue)
	if err != nil {
		logger.Error("%s", err.Error())

	}
	if layers.CompareFeatures(&[]layers.MFeatures{testBody9}, &[]layers.MFeatures{origFeatures}) {
		logger.Debug("failed concat test 9")
		return false
	}
	bsql.addToConfirmInjectionHistory(paramValue, false)

	return true
}

func (bsql *classBlindSQLInj) testInjection(varIndex int, quoteChar string, likeInjection bool) bool {

	var confirmed = false
	var confirmResult = false
	for {
		confirmResult = bsql.confirmInjection(varIndex, quoteChar, likeInjection, confirmed)
		if !confirmResult {
			return false
		}
		if confirmed {
			logger.Debug("second round finished with success")
			break
		} else {
			logger.Debug("first round finished with success")
			confirmed = true
		}
	}
	// report sql injection
	// bsql.alert(confirmResult)

	bsql.confirmInjectionHistory = []InjectionResult{}
	return true
}

func (bsql *classBlindSQLInj) testInjectionWithOR(varIndex int, quoteChar string, dontCommentRestOfQuery bool) bool {

	var confirmed = false
	var confirmResult = false
	for {
		confirmResult = bsql.confirmInjectionWithOR(varIndex, quoteChar, confirmed, dontCommentRestOfQuery)
		if !confirmResult {
			return false
		}
		if confirmed {
			logger.Debug("second round finished with success")
			break
		} else {
			logger.Debug("first round finished with success")
			confirmed = true
		}
	}
	// report sql injection
	// bsql.alert(confirmResult)

	bsql.confirmInjectionHistory = []InjectionResult{}
	return true
}

func (bsql *classBlindSQLInj) testInjectionStringConcatenation(varIndex int) bool {

	var confirmed = false
	var confirmResult = false
	for {
		confirmResult = bsql.confirmInjectionStringConcatenation(varIndex, confirmed)
		if !confirmResult {
			return false
		}
		if confirmed {
			logger.Debug("second round finished with success")
			break
		} else {
			logger.Debug("first round finished with success")
			confirmed = true
		}
	}
	// report sql injection
	// bsql.alert(confirmResult)

	bsql.confirmInjectionHistory = []InjectionResult{}
	return true
}

func (bsql *classBlindSQLInj) startTesting() bool {
	if bsql.origValue == "" {
		bsql.origValue = "1"
		bsql.isNumeric = true
	}
	for _, p := range bsql.variations.Params {
		if bsql.foundVulnOnVariation {
			break
		}
		if !bsql.checkIfResponseIsStable(p.Index) {
			return false
		}
		var doBooleanTests = true
		// var doTimingTests = true
		// var doTimingTestsMySQL = true
		// var doTimingTestsMySQLBenchmark = false
		// var doTimingTestsMSSQL = true
		// var doTimingTestsMSSQLExtra = false
		// var doTimingTestsPostgreSQL = true
		// var doTimingTestsPostgreSQLExtra = false
		// var doTimingTestsOracle = true
		// var doTimingTestsRails = true
		// var doOOBTests = false
		// var doOddEvenTests = false
		if doBooleanTests {
			// boolean tests
			if bsql.inputIsStable {
				// numeric
				if bsql.isNumeric && bsql.testInjection(p.Index, "", false) {
					return true
				}
				// single quote
				if bsql.testInjection(p.Index, "'", false) {
					return true
				}
				// double quote
				if bsql.testInjection(p.Index, `"`, false) {
					return true
				}
				// single quote, inside like
				if bsql.testInjection(p.Index, "'", true) {
					return true
				}
				// no quotes
				// if (this.testInjectionWithOR(i, '')) return true;
				// no quotes (don't comment rest of query)
				if bsql.testInjectionWithOR(p.Index, "'", true) {
					return true
				}
				// string concatenation PostgreSQL, Oracle (doesn't work on MySQL)
				if !bsql.isNumeric && bsql.origValue != "" && len(bsql.origValue) >= 2 && bsql.testInjectionStringConcatenation(p.Index) {
					return true
				}
				// for special named parameters make the order/group by tests

			}
		}
	}
	return false
}

// var DefaultProxy = ""
var Cert string
var Mkey string

func Sql_inject_Vaild(args interface{}) (*util.ScanResult, error) {
	var err error
	var variations *util.PostData
	var ContentType string
	var BlindSQL classBlindSQLInj
	var hostid int64
	// var blastIters interface{}
	util.Setup()
	group := args.(plugin.GroupData)
	// ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	ctx := *group.Pctx

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	session := group.GroupUrls.(map[string]interface{})
	url := session["url"].(string)
	method := session["method"].(string)
	headers, _ := util.ConvertHeaders(session["headers"].(map[string]interface{}))
	body := []byte(session["data"].(string))
	Cert = group.HttpsCert
	Mkey = group.HttpsCertKey
	sess := fastreq.GetSessionByOptions(
		&fastreq.ReqOptions{
			Timeout:       10 * time.Second,
			AllowRedirect: true,
			Proxy:         DefaultProxy,
			Cert:          Cert,
			PrivateKey:    Mkey,
		})

	if value, ok := session["hostid"].(int64); ok {
		hostid = value
	}

	if value, ok := session["hostid"].(json.Number); ok {
		hostid, _ = value.Int64()
	}

	// variations,err = util.ParseUri(url)
	// BlindSQL.variations =
	if value, ok := headers["Content-Type"]; ok {
		ContentType = value
	}
	variations, err = util.ParseUri(url, body, method, ContentType)
	//赋值
	BlindSQL.variations = variations
	BlindSQL.lastJob.Layer.Sess = sess
	BlindSQL.TargetUrl = url
	BlindSQL.lastJob.Layer.Method = method
	BlindSQL.lastJob.Layer.ContentType = ContentType
	BlindSQL.lastJob.Layer.Headers = headers
	BlindSQL.lastJob.Layer.Body = body

	if BlindSQL.startTesting() {
		// println(hostid)
		// println("发现sql漏洞")
		//....................
		Result := util.VulnerableTcpOrUdpResult(url,
			"sql inject Vulnerable",
			[]string{string(BlindSQL.lastJob.Features.Request.String())},
			[]string{string(BlindSQL.lastJob.Features.Response.String())},
			"high",
			hostid)
		return Result, err
	} else {
		errtester := ClassSQLErrorMessages{
			TargetUrl:  url,
			LastJob:    &BlindSQL.lastJob,
			variations: BlindSQL.variations,
		}
		if errtester.startTesting() {
			Result := util.VulnerableTcpOrUdpResult(url,
				"sql error inject Vulnerable",
				[]string{string(errtester.LastJob.Features.Request.String())},
				[]string{string(errtester.LastJob.Features.Response.String())},
				"high",
				hostid)
			return Result, err
		}

	}

	return nil, err
}
