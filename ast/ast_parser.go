package ast

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	log "wenscan/log"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"github.com/thoas/go-funk"
	"github.com/tidwall/btree"
	"golang.org/x/net/html"
)

type JsonUrl struct {
	Url     string                 `json:"url"`
	MetHod  string                 `json:"method"`
	Headers map[string]interface{} `json:"headers"`
	Data    string                 `json:"data"` //post数据
	Source  string                 `json:"source"`
}

type Attribute struct {
	Key string
	Val string
}

type Node struct {
	Idx        int
	Tagname    string
	Content    string
	Attributes *[]Attribute
	Children   []*Node
}

type Occurence struct {
	Type     string
	Position int
	Details  Node
}

type Parser struct {
	tokenizer *btree.BTree
}

// byKeys is a comparison function that compares item keys and returns true
// when a is less than b.
func ByKeys(a, b interface{}) bool {
	i1, i2 := a.(*Node), b.(*Node)
	return i1.Idx <= i2.Idx
}

//Duplicate 去除重复元素
func Duplicate(a interface{}) (ret []interface{}) {
	va := reflect.ValueOf(a)
	for i := 0; i < va.Len(); i++ {
		if i > 0 && reflect.DeepEqual(va.Index(i-1).Interface(), va.Index(i).Interface()) {
			continue
		}
		ret = append(ret, va.Index(i).Interface())
	}
	return ret
}

//AnalyseJs Js的ast语法分析，主要目的是抓取变量，返回变量数组
func AnalyseJs(script string) []string {
	var params = []string{}
	var vardiscover bool
	ast, err := js.Parse(parse.NewInputString(script))
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("Scope:", ast.Scope.String())
	fmt.Println("JS:", ast.String())
	//ast.BlockStmt.String()
	l := js.NewLexer(parse.NewInputString(script))
	for {
		tt, text := l.Next()
		switch tt {
		case js.ErrorToken:
			if l.Err() != io.EOF {
				fmt.Println("Error on line:", l.Err())
			}
			return params
		case js.VarToken:
			vardiscover = true
		case js.StringToken:
			str := string(text)
			if vardiscover {
				params = append(params, str)
			}
			vardiscover = false
		}
	}
}

//GetHtmlParams 获取html的参数
func GetHtmlParams(tokenizer *btree.BTree) []interface{} {
	var params = []string{}
	//['url', 'id', 'myfunc', 'strs', 'str', 'i', 'strSub','testName']
	tokenizer.Ascend(nil, func(item interface{}) bool {
		kvi := item.(*Node)
		// log.Debug("Tagname:", kvi.Tagname, "Content:", kvi.Content, "Attribute:", kvi.Attributes, "\n")
		if kvi.Tagname == "input" {
			for _, Attribute := range *kvi.Attributes {
				if Attribute.Key == "name" {
					params = append(params, Attribute.Val)
				}
			}
		} else if kvi.Tagname == "script" {
			log.Debug("Content:", kvi.Content)
			// program, err := parser.ParseFile(nil, "", kvi.Content, 0)
			// if err != nil {
			// 	panic(err)
			// }
			params = append(params, AnalyseJs(kvi.Content)...)
		}
		return true
	})
	return Duplicate(params)
}

//HttpParser http标签过滤
func (parser *Parser) HttpParser(body string) bool {
	//color.Red(body)
	Tree := btree.New(ByKeys)
	parser.tokenizer = btree.New(ByKeys)
	z := html.NewTokenizer(strings.NewReader(body))
	var i = 0
	for {
		i++
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			goto processing
		case html.TextToken:
			log.Debug("html.TextToken:%s", string(z.Raw()))
			if field, ok := Tree.Max().(*Node); ok {
				field.Content = string(z.Raw())
			}
		case html.StartTagToken:
			log.Debug("html.StartTagToken:%s", string(z.Raw()))
			Attributes := make([]Attribute, 0)
			array, _ := z.TagName()
			for {
				key, val, moreAttr := z.TagAttr()
				if moreAttr {
					tmp := Attribute{Key: string(key), Val: string(val)}
					Attributes = append(Attributes, tmp)
				} else {
					tmp := Attribute{Key: string(key), Val: string(val)}
					Attributes = append(Attributes, tmp)
					break
				}
			}
			cx := string(array)
			if cx == "br" {
				log.Debug(" html.StartTagToken 发现br标签,忽略")
			} else {
				Tree.Set(&Node{Idx: i, Tagname: cx, Content: "", Attributes: &Attributes})
			}

		case html.EndTagToken:
			name, _ := z.TagName()
			log.Debug("html.EndTagToken:%s", string(z.Raw()))
			for {
				if field, ok := Tree.Max().(*Node); ok {
					if field.Tagname == string(name) {
						parser.tokenizer.Set(Tree.PopMax())
						break
					}
					//color.Red("field.Tagname:%s  local TagName:%s", field.Tagname, name)
					parser.tokenizer.Set(Tree.PopMax())
				}
			}

		case html.SelfClosingTagToken:
			log.Debug("html.SelfClosingTagToken:%s", string(z.Raw()))
			Attributes := make([]Attribute, 0)
			array, _ := z.TagName()
			for {
				key, val, moreAttr := z.TagAttr()
				if moreAttr {
					tmp := Attribute{Key: string(key), Val: string(val)}
					Attributes = append(Attributes, tmp)
				} else {
					tmp := Attribute{Key: string(key), Val: string(val)}
					Attributes = append(Attributes, tmp)
					break
				}
			}
			cx := string(array)
			Tree.Set(&Node{Idx: i, Tagname: cx, Content: "", Attributes: &Attributes})
			name, _ := z.TagName()
			for {
				if field, ok := Tree.Max().(*Node); ok {
					if field.Tagname == string(name) {
						parser.tokenizer.Set(Tree.PopMax())
						break
					}
					parser.tokenizer.Set(Tree.PopMax())
				}
			}

		case html.CommentToken:
			Attributes := make([]Attribute, 0)
			log.Debug("html.CommentToken:%s", string(z.Raw()))
			parser.tokenizer.Set(&Node{Idx: i, Tagname: "#comment", Content: string(z.Raw()), Attributes: &Attributes})
		}

	}
processing:
	return true
}

//GetTokenizer 获取节点
func (parser *Parser) GetTokenizer() []Node {
	var tokens []Node
	parser.tokenizer.Ascend(nil, func(item interface{}) bool {
		kvi := item.(*Node)
		//log.Debug("Tagname:", kvi.Tagname, "Content:", kvi.Content, "Attribute:", kvi.Attributes, "\n")
		tokens = append(tokens, *kvi)
		return true
	})
	return tokens
}

//SearchInputInResponse 搜索响应信息的位置
func SearchInputInResponse(input string, body string) []Occurence {
	parse := Parser{}
	Occurences := []Occurence{}
	Index := 0
	if len(body) == 0 {
		log.Error("SearchInputInResponse 获取body失败")
		return Occurences
	}
	parse.HttpParser(body)
	tokens := parse.GetTokenizer()
	// fmt.Println(aurora.Cyan(tokens))
	if len(tokens) == 0 {
		log.Error("SearchInputInResponse tokens 没有发现节点")
		return Occurences
	}
	for _, token := range tokens {
		tagname := token.Tagname
		// if token.Tagname == "img" {
		// 	for _, v := range *token.Attributes {
		// 		if v.Key == "onerror" {
		// 			fmt.Println("find")
		// 		}
		// 	}
		// }
		content := token.Content
		attibutes := token.Attributes
		if input == tagname {
			Occurences = append(Occurences, Occurence{Type: "intag", Position: Index, Details: token})
		} else if funk.Contains(content, input) {
			//log.Info("tagName: %s", tagname)
			if tagname == "comment" {
				Occurences = append(Occurences, Occurence{Type: "comment", Position: Index, Details: token})
			} else if tagname == "script" {
				Occurences = append(Occurences, Occurence{Type: "script", Position: Index, Details: token})
			} else if tagname == "style" {
				Occurences = append(Occurences, Occurence{Type: "html", Position: Index, Details: token})
			} else {
				Occurences = append(Occurences, Occurence{Type: "html", Position: Index, Details: token})
				for _, attibute := range *attibutes {
					//log.Info("attibute.Val: %s", attibute.Val)
					if input == attibute.Key {
						detail := Node{Tagname: tagname, Content: "key", Attributes: &[]Attribute{{Key: attibute.Key, Val: attibute.Val}}}
						Occurences = append(
							Occurences,
							Occurence{
								Type:     "attibute",
								Position: Index,
								Details:  detail})
						//使用funk.Contains是因为有可能是Val是脚本
					} else if funk.Contains(attibute.Val, input) {
						detail := Node{Tagname: tagname, Content: "val", Attributes: &[]Attribute{{Key: attibute.Key, Val: attibute.Val}}}
						Occurences = append(
							Occurences,
							Occurence{
								Type:     "attibute",
								Position: Index,
								Details:  detail})
					}
				}
			}
		} else {
			for _, attibute := range *attibutes {
				if input == attibute.Key {
					detail := Node{Tagname: tagname, Content: "key", Attributes: &[]Attribute{{Key: attibute.Key, Val: attibute.Val}}}
					Occurences = append(
						Occurences,
						Occurence{
							Type:     "attibute",
							Position: Index,
							Details:  detail})
				} else if funk.Contains(attibute.Val, input) {
					detail := Node{Tagname: tagname, Content: "val", Attributes: &[]Attribute{{Key: attibute.Key, Val: attibute.Val}}}
					Occurences = append(
						Occurences,
						Occurence{
							Type:     "attibute",
							Position: Index,
							Details:  detail})
				}
			}
		}
		if len(Occurences) > 0 {
			Index++
		}
	}
	return Occurences
}

//AnalyseJSByFlag 分析js语法获取部分语法数据
func AnalyseJSFuncByFlag(input string, script string) (string, error) {
	ast, err := js.Parse(parse.NewInputString(script))
	if err != nil {
		return "", err
	}
	var newpayload bytes.Buffer
	fmt.Println("Scope:", ast.Scope.String())
	fmt.Println("JS:", ast.String())
	//ast.BlockStmt.String()
	l := js.NewLexer(parse.NewInputString(script))
	for {
		tt, text := l.Next()
		switch tt {
		case js.ErrorToken:
			if l.Err() != io.EOF {
				fmt.Println("Error on line:", l.Err())
			}
			return newpayload.String(), nil
		case js.IdentifierToken:
			str := string(text)
			if funk.Contains(str, input) {
				log.Info("flag %s exists in a Identifier ", str)
			}
		case js.StringToken:
			str := string(text)
			if funk.Contains(str, input) {
				//检测flag是否在闭合函数中
				reg := "\\(function(.*?)Stmt\\({(.*?)" + str + "(.*?)}\\)\\)"
				match, _ := regexp.MatchString(reg, ast.String())
				if match {
					log.Info("var %s flag exists in a closed function", str)

					leftcloser := JsContexterLeft(input, ast.JS())
					Rightcloser := JsContexterRight(input, ast.JS())
					//判断是否是单引号还是双引号的字符串变量
					if funk.Contains(str, "'") {
						newpayload.WriteString("';" + leftcloser + " console.log(\"" + input + "\"); " + Rightcloser + "//\\")
					} else {
						newpayload.WriteString("\"\";" + leftcloser + " console.log('" + input + "'); " + Rightcloser + "//\\")
					}
				} else {
					log.Info("var %s flag exists in Statement", str)
					//判断是否是单引号还是双引号的字符串变量
					if funk.Contains(str, "'") {
						newpayload.WriteString("'; console.log('" + input + "');//")
					} else {
						newpayload.WriteString("\"\";%0aconsole.log('" + input + "');//")
					}
				}
			}
		}
	}

}

// 反转字符串
func reverseString(s string) string {
	runes := []rune(s)
	for from, to := 0, len(runes)-1; from < to; from, to = from+1, to-1 {
		runes[from], runes[to] = runes[to], runes[from]
	}
	return string(runes)
}

func stripper(str string, substring rune, direction string) string {
	done := false
	var (
		strippedString bytes.Buffer
		s              bytes.Buffer
		retstring      bytes.Buffer
	)

	if direction == "right" {
		s.WriteString(reverseString(str))
	}
	for _, char := range s.String() {
		if char == substring && !done {
			done = true
		} else {
			strippedString.WriteString(string(char))
		}
	}
	if direction == "right" {
		retstring.WriteString(reverseString(strippedString.String()))
	}
	return retstring.String()
}

//JsContexter 生成左半边的闭合xss payload
func JsContexterLeft(xsschecker string, script string) string {
	var breaker bytes.Buffer
	broken := strings.Split(script, xsschecker)
	pre := broken[0]
	re := regexp.MustCompile(`(?s)\{.*?\}|(?s)\(.*?\)|(?s)".*?"|(?s)\'.*?\'`)
	s := re.ReplaceAllString(pre, "")
	num := 0
	for idx, char := range s {
		if char == '{' {
			breaker.WriteString("}")
		} else if char == '(' {
			breaker.WriteString(";)")
		} else if char == '[' {
			breaker.WriteString("]")
		} else if char == '/' {
			if idx+1 <= len(s) {
				if s[idx+1] == '*' {
					breaker.WriteString("/*")
				}
			}
		} else if char == '}' {
			c := stripper(breaker.String(), '}', "right")
			breaker.Reset()
			breaker.WriteString(c)
		} else if char == ')' {
			c := stripper(breaker.String(), ')', "right")
			breaker.Reset()
			breaker.WriteString(c)
		} else if char == ']' {
			c := stripper(breaker.String(), ']', "right")
			breaker.Reset()
			breaker.WriteString(c)
		}
		num++
	}
	return reverseString(breaker.String())
}

//JsContexterRight 生成右半边的闭合xss payload
func JsContexterRight(xsschecker string, script string) string {
	var breaker bytes.Buffer
	var count int = 0
	var s string
	bFriststr := "function a(){"
	broken := strings.Split(script, xsschecker)
	pre := broken[1]
	pre0 := broken[0] //检测else 对于flag左半边边是否是子集    比如 if else 外部有个 if 包含了
	//fmt.Println(pre0)
	/*
		pre0 == function loadTest () { var time = 11; if (1) { if (time < 20) { if (1) { var x = '
	*/
	Lpayload := strings.Count(pre0, "{")

	//pre = "'); }; } else { var x = '2222222'; }; };"
	//re := regexp.MustCompile(`(?s)\{.*?\}|(?s)\(.*?\)|(?s)".*?"|(?s)\'.*?\'`)
	//// '; }; } else { var x = '2222222'; }; };    //过滤前
	//// 2222222'; }; }; 					//过滤后
	///这里可以过滤到else有什么问题可以在这里调试
	elses := strings.Split(pre, "else")
	//这里存在else的因素所以必须想办法使生成的payload让这个函数闭合，我采取的思路就是else右半边的 '}' 与 左半边的 '}' 相减，多出来的数目在payload后面添加 }
	if len(elses) >= 2 {
		//计算else左边反括号数量
		LbracketsCount := strings.Count(elses[0], "}")
		//计算else右边反括号数量
		RbracketsCount := strings.Count(elses[1], "}")
		//计算闭合
		cot := Lpayload - RbracketsCount
		count = RbracketsCount - LbracketsCount + 1 - 1 - cot // + 1 是因为else的存在，-1是因为我函数开头以 function%20a(){ 的存在 ,cot判断else是否有外部闭合的情况
		s = pre
	} else {
		s = strings.Replace(pre, "}", "", 1) //1是因为我函数开头以 function%20a(){ 的存在
	}
	num := 0
	for idx, char := range s {
		if char == '}' {
			breaker.WriteString(" {)1(fi")
		} else if char == ')' {
			breaker.WriteString("(") //这个估计改下1(
		} else if char == ']' {
			breaker.WriteString("[")
		} else if char == '*' {
			if idx+1 <= len(s) {
				if s[idx+1] == '/' {
					breaker.WriteString("*/")
				}
			}
		} else if char == '{' {
			c := stripper(breaker.String(), '{', "left")
			breaker.Reset()
			breaker.WriteString(c)
		} else if char == '(' {
			c := stripper(breaker.String(), '(', "left")
			breaker.Reset()
			breaker.WriteString(c)
		} else if char == '[' {
			c := stripper(breaker.String(), '[', "left")
			breaker.Reset()
			breaker.WriteString(c)
		}
		num++
	}
	var exportbyelse bytes.Buffer
	for z := 0; z < count; z++ {
		exportbyelse.WriteString("}")
	}
	return bFriststr + reverseString(breaker.String()) + exportbyelse.String()
}
