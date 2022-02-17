package JsonPoc

// import (
// 	"go/parser"
// 	"io/ioutil"
// 	"net/http"
// 	"net/url"
// 	"regexp"

// 	"github.com/dop251/goja/ast"
// )

// func CheckSenseJsonp(jsUrl string) (bool, error) {
// 	queryMap, domainString, err := UrlParser(jsUrl)
// 	if err != nil {
// 		return false, err
// 	}

// 	isCallback, callbackFuncName, err := CheckJSIsCallback(queryMap)

// 	if isCallback {
// 		//	referer： host 请求
// 		normalRespContent, err := GetJsResponse(jsUrl, domainString)
// 		if err != nil {
// 			return false, err
// 		}
// 		isJsonpNormal, err := CheckJsRespAst(normalRespContent, callbackFuncName)
// 		if err != nil {
// 			return false, err
// 		}
// 		// 如果包含敏感字段 将 referer 置空 再请求一次
// 		if isJsonpNormal {
// 			noRefererContent, err := GetJsResponse(jsUrl, "")
// 			if err != nil {
// 				return false, err
// 			}
// 			isJsonp, err := CheckJsRespAst(noRefererContent, callbackFuncName)
// 			if err != nil {
// 				return false, err
// 			}
// 			return isJsonp, nil
// 		}

// 	}
// 	return false, nil
// }

// func UrlParser(jsUrl string) (url.Values, string, error) {
// 	urlParser, err := url.Parse(jsUrl)
// 	if err != nil {
// 		return nil, "", err
// 	}
// 	// 拼接原始referer
// 	domainString := urlParser.Scheme + "://" + urlParser.Host
// 	return urlParser.Query(), domainString, nil
// }

// func CheckJSIsCallback(queryMap url.Values) (bool, string, error) {
// 	var re = regexp.MustCompile(`(?m)(?i)(callback)|(jsonp)|(^cb$)|(function)`)
// 	for k, v := range queryMap {
// 		regResult := re.FindAllString(k, -1)
// 		if len(regResult) > 0 && len(v) > 0 {
// 			return true, v[0], nil
// 		}
// 	}
// 	return false, "", nil
// }

// func CheckIsSensitiveKey(key string) (bool, error) {
// 	var re = regexp.MustCompile(`(?m)(?i)(uid)|(userid)|(user_id)|(nin)|(name)|(username)|(nick)`)
// 	regResult := re.FindAllString(key, -1)
// 	if len(regResult) > 0 {
// 		return true, nil
// 	}
// 	return false, nil
// }

// func GetJsResponse(jsUrl string, referer string) (string, error) {
// 	req, err := http.NewRequest("GET", jsUrl, nil)
// 	if err != nil {
// 		return "", nil
// 	}
// 	req.Header.Set("Referer", referer)
// 	resp, err := goHTTPClient.Do(req)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()
// 	body, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return "", err
// 	}
// 	if resp.StatusCode == 200 {
// 		return string(body), nil
// 	}
// 	return "", nil
// }

// func CheckJsRespAst(content string, funcName string) (bool, error) {
// 	// 解析js语句，生成 *ast.Program 或 ErrorList
// 	program, err := parser.ParseFile(nil, "", content, 0)
// 	if err != nil {
// 		return false, err
// 	}
// 	if len(program.Body) > 0 {
// 		statement := program.Body[0]
// 		expression := statement.(*ast.ExpressionStatement).Expression
// 		expName := expression.(*ast.CallExpression).Callee.(*ast.Identifier).Name
// 		// 表达式中函数名与query函数名不一致 直接返回false
// 		if funcName != expName {
// 			return false, err
// 		}
// 		argList := expression.(*ast.CallExpression).ArgumentList
// 		for _, arg := range argList {
// 			result := DealAstExpression(arg)
// 			if result != true {
// 				continue
// 			}
// 			return result, nil
// 		}
// 	}
// 	//ast树为空 直接返回
// 	return false, nil
// }

// func DealAstExpression(expression ast.Expression) bool {
// 	objectLiteral, isObjectLiteral := expression.(*ast.ObjectLiteral)
// 	if isObjectLiteral {
// 		values := objectLiteral.Value
// 		for _, value := range values {
// 			result := DealAstProperty(value)
// 			if result != true {
// 				continue
// 			}
// 			return result
// 		}
// 	}
// 	return false
// }
// func DealAstProperty(value ast.Property) bool {
// 	secondLevelValue := value.Value
// 	// 表达式中是数组/对象的 递归
// 	objectLiteral, isObjectLiteral := secondLevelValue.(*ast.ObjectLiteral)
// 	arrayLiteral, isArrayLiteral := secondLevelValue.(*ast.ArrayLiteral)
// 	stringLiteral, isStringLiteral := secondLevelValue.(*ast.StringLiteral)
// 	numberLiteral, isNumberLiteral := secondLevelValue.(*ast.NumberLiteral)
// 	if isObjectLiteral {
// 		thirdLevelValue := objectLiteral.Value
// 		for _, v := range thirdLevelValue {
// 			DealAstProperty(v)
// 		}
// 	} else if isArrayLiteral {
// 		thirdLevelValue := arrayLiteral.Value
// 		for _, v := range thirdLevelValue {
// 			DealAstExpression(v)
// 		}
// 	} else if isStringLiteral {
// 		// 表达式中value为字符串/数字的 才会检测key value
// 		thirdLevelValue := stringLiteral.Value
// 		isSensitiveKey, _ := CheckIsSensitiveKey(value.Key)
// 		if isSensitiveKey && thirdLevelValue != "" {
// 			return true
// 		}
// 	} else if isNumberLiteral {
// 		thirdLevelValue := numberLiteral.Value
// 		isSensitiveKey, _ := CheckIsSensitiveKey(value.Key)
// 		if isSensitiveKey && thirdLevelValue != 0 {
// 			return true
// 		}
// 	}
// 	return false
// }
