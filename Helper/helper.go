package Helper

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	log "wenscan/Log"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"github.com/thoas/go-funk"
	"github.com/tidwall/btree"
	"golang.org/x/net/html"
)

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
func AnalyseJs(program *ast.Program) []string {
	var params = []string{}
	for _, Declaration := range program.DeclarationList {
		switch c := Declaration.(type) {
		case *ast.VariableDeclaration:
			for _, v := range c.List {
				params = append(params, v.Name.String())
				//fmt.Println("发现变量声明", v.Name.String())
				switch c := v.Initializer.(type) {
				case *ast.FunctionLiteral:
					//fmt.Println("发现函数声明，正在提取函数内的变量", c.DeclarationList)
					for _, Declaration := range c.DeclarationList {
						switch c := Declaration.(type) {
						case *ast.VariableDeclaration:
							for _, v := range c.List {
								//fmt.Println("函数内的变量", v.Name.String())
								params = append(params, v.Name.String())
							}
						}
					}
				}
			}
		case *ast.FunctionDeclaration:
			for _, Declaration := range c.Function.DeclarationList {
				switch c := Declaration.(type) {
				case *ast.VariableDeclaration:
					for _, v := range c.List {
						//fmt.Println("发现属性FunctionDeclaration内变量声明", v.Name.String())
						params = append(params, v.Name.String())
					}
				}
			}
		}
	}
	return params
}

//GetHtmlParams 获取html的参数
func GetHtmlParams(tokenizer *btree.BTree) []interface{} {
	var params = []string{}
	//['url', 'id', 'myfunc', 'strs', 'str', 'i', 'strSub','testName']
	tokenizer.Ascend(nil, func(item interface{}) bool {
		kvi := item.(*Node)
		log.Debug("Tagname:", kvi.Tagname, "Content:", kvi.Content, "Attribute:", kvi.Attributes, "\n")
		if kvi.Tagname == "input" {
			for _, Attribute := range *kvi.Attributes {
				if Attribute.Key == "name" {
					params = append(params, Attribute.Val)
				}
			}
		} else if kvi.Tagname == "script" {
			log.Debug("Content:", kvi.Content)
			program, err := parser.ParseFile(nil, "", kvi.Content, 0)
			if err != nil {
				panic(err)
			}
			params = append(params, AnalyseJs(program)...)
		}
		return true
	})
	return Duplicate(params)
}

//HttpParser http标签过滤
func (parser *Parser) HttpParser(body string) bool {
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
			Tree.Set(&Node{Idx: i, Tagname: cx, Content: "", Attributes: &Attributes})

		case html.EndTagToken:
			name, _ := z.TagName()
			log.Debug("html.EndTagToken:%s", string(z.Raw()))
			for {
				if field, ok := Tree.Max().(*Node); ok {
					if field.Tagname == string(name) {
						parser.tokenizer.Set(Tree.PopMax())
						break
					}
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
		log.Debug("Tagname:", kvi.Tagname, "Content:", kvi.Content, "Attribute:", kvi.Attributes, "\n")
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
	parse.HttpParser(body)
	tokens := parse.GetTokenizer()
	for _, token := range tokens {
		tagname := token.Tagname
		content := token.Content
		attibutes := token.Attributes
		if input == tagname {
			Occurences = append(Occurences, Occurence{Type: "intag", Position: Index, Details: token})
		} else if funk.Contains(content, input) {
			if tagname == "#comment" {
				Occurences = append(Occurences, Occurence{Type: "comment", Position: Index, Details: token})
			} else if tagname == "script" {
				Occurences = append(Occurences, Occurence{Type: "script", Position: Index, Details: token})
			} else if tagname == "style" {
				Occurences = append(Occurences, Occurence{Type: "html", Position: Index, Details: token})
			} else {
				Occurences = append(Occurences, Occurence{Type: "html", Position: Index, Details: token})
				for _, attibute := range *attibutes {
					if input == attibute.Key {
						detail := Node{Tagname: "attibute", Content: "key", Attributes: &[]Attribute{{Key: attibute.Key, Val: attibute.Val}}}
						Occurences = append(
							Occurences,
							Occurence{
								Type:     "attibute",
								Position: Index,
								Details:  detail})
					} else if input == attibute.Val {
						detail := Node{Tagname: "attibute", Content: "val", Attributes: &[]Attribute{{Key: attibute.Key, Val: attibute.Val}}}
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
					detail := Node{Tagname: "attibute", Content: "key", Attributes: &[]Attribute{{Key: attibute.Key, Val: attibute.Val}}}
					Occurences = append(
						Occurences,
						Occurence{
							Type:     "attibute",
							Position: Index,
							Details:  detail})
				} else if input == attibute.Val {
					detail := Node{Tagname: "attibute", Content: "val", Attributes: &[]Attribute{{Key: attibute.Key, Val: attibute.Val}}}
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

func checkIfstmtExistsFlag(leftpayload bytes.Buffer, rightpayload bytes.Buffer, input string, Body js.IStmt) {
	switch a := Body.(type) {
	case *js.BlockStmt:
		leftpayload.WriteString("}")
		rightpayload.WriteString("{")
		for _, item := range a.List {
			switch c := item.(type) {
			case *js.VarDecl:
				for _, a := range c.List {
					if funk.Contains(a.Default.JS(), input) {
						sd := leftpayload.Bytes()[len(leftpayload.Bytes())-1]
						leftpayload.Reset()
						leftpayload.WriteByte(sd)
					}
				}
			}
		}

	}
}

// for _, item := range ast.BlockStmt.List {
// 	switch a := item.(type) {
// 	case *js.FuncDecl:
// 		leftpayload.WriteString("}")
// 		rightpayload.WriteString("{")
// 		for _, c := range a.Body.List {
// 			switch sc := c.(type) {
// 			case *js.IfStmt:
// 				//判断flag是否在变量内 if（xxx）{ var xx = flag} else { xxxxx }' block
// 				fmt.Println("IfStmt:", sc.Body.JS())
// 				if sc.Else == nil {
// 					checkIfstmtExistsFlag(leftpayload, rightpayload, input, sc.Body)
// 					AnalyseJSFuncByFlag(leftpayload, rightpayload, input, script)
// 				}
// 			}
// 		}

// 	}
// }
//var left bytes.Buffer

//AnalyseJSByFlag 分析js语法获取部分语法数据
func AnalyseJSFuncByFlag(input string, script string) (string, error) {
	ast, err := js.Parse(parse.NewInputString(script))
	if err != nil {
		panic(err.Error())
	}
	var newpayload bytes.Buffer
	fmt.Println("Scope:", ast.Scope.String())
	fmt.Println("JS:", ast.String())
	ast.BlockStmt.String()
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
						newpayload.WriteString("%27;" + leftcloser + "%0aconsole.log('" + input + "');%0a" + Rightcloser + "//\\")
					} else {
						newpayload.WriteString("\"\";" + leftcloser + "%0aconsole.log('" + input + "');%0a" + Rightcloser + "//\\")
					}
				} else {
					log.Info("var %s flag exists in Statement", str)
					//判断是否是单引号还是双引号的字符串变量
					if funk.Contains(str, "'") {
						newpayload.WriteString("%27;%0aconsole.log('" + input + "');//")
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
	bFrist := true
	bFriststr := "function%20a(){"
	broken := strings.Split(script, xsschecker)
	pre := broken[1]
	re := regexp.MustCompile(`(?s)\{.*?\}|(?s)\(.*?\)|(?s)".*?"|(?s)\'.*?\'`)
	s := re.ReplaceAllString(pre, "")
	num := 0
	for idx, char := range s {
		if char == '}' {
			if bFrist {
				bFrist = false
			} else {
				breaker.WriteString("a0%{)1(fi")
			}
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
	return bFriststr + reverseString(breaker.String())
}
