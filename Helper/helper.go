package Helper

import (
	"reflect"
	"strings"

	log "wenscan/Log"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
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
			log.Info("Content:", kvi.Content)
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
			log.Debug("html.TextToken:", string(z.Raw()))
			if field, ok := Tree.Max().(*Node); ok {
				field.Content = string(z.Raw())
			}
		case html.StartTagToken:
			log.Debug("html.StartTagToken:", string(z.Raw()))
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
			log.Debug("html.EndTagToken:", string(z.Raw()))
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
			log.Debug("html.SelfClosingTagToken:", string(z.Raw()))
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
			log.Debug("html.CommentToken:", string(z.Raw()))
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
		} else if input == content {
			if tagname == "#comment" {
				Occurences = append(Occurences, Occurence{Type: "comment", Position: Index, Details: token})
			} else if tagname == "script" {
				Occurences = append(Occurences, Occurence{Type: "script", Position: Index, Details: token})
			} else if tagname == "style" {
				Occurences = append(Occurences, Occurence{Type: "html", Position: Index, Details: token})
			} else {
				Occurences = append(Occurences, Occurence{Type: "html", Position: Index, Details: token})
			}
		} else {
			for _, attibute := range *attibutes {
				if input == attibute.Key {
					detail := Node{Tagname: tagname, Content: "key", Attributes: &[]Attribute{Attribute{Key: attibute.Key, Val: attibute.Val}}}
					Occurences = append(
						Occurences,
						Occurence{
							Type:     "attibute",
							Position: Index,
							Details:  detail})
				} else if input == attibute.Val {
					detail := Node{Tagname: tagname, Content: "key", Attributes: &[]Attribute{Attribute{Key: attibute.Key, Val: attibute.Val}}}
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
