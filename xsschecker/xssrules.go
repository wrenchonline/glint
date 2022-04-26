package xsschecker

//此包专门针对xss更具上下文设置payload，智能化的框架

// func init() {

// 	jsbody := `callbackFunction(({"hh":"1","name":"fsdfa"}))`
// 	var params = []string{}
// 	var vardiscover bool
// 	o := js.Options{}
// 	ast, err := js.Parse(parse.NewInputString(jsbody), o)
// 	if err != nil {
// 		panic(err.Error())
// 	}

// 	fmt.Println("Scope:", ast.Scope.String())
// 	fmt.Println("Scope Func:", ast.Scope.Func.String())

// 	fmt.Println("JS:", ast.String())
// 	//ast.BlockStmt.String()
// 	l := js.NewLexer(parse.NewInputString(jsbody))
// 	for {
// 		tt, text := l.Next()
// 		fmt.Printf("value %v type %v \n", string(text), tt)

// 		switch tt {
// 		case js.ErrorToken:
// 			if l.Err() != io.EOF {
// 				fmt.Println("Error on line:", l.Err())
// 			}
// 			//t.Log("ok")
// 			break
// 		case js.VarToken:
// 			vardiscover = true
// 		case js.StringToken:
// 			str := string(text)
// 			if vardiscover {
// 				params = append(params, str)
// 			}
// 			vardiscover = false
// 		case js.IdentifierToken:
// 			// fmt.Println("IdentifierToken", string(text))
// 		}
// 	}
// }
