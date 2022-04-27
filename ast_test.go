package main

import (
	"fmt"
	"io"
	"testing"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

func Test_Functiondiscover(t *testing.T) {
	jsbody := `
    (function () {
		const App = {
		  view: function () {
			return m("div", { class: "window" }, [
			  m(TitleBar),
			  m(WindowBody),
			  m(StatusBar)
			])
		  }
		}
  
		const TitleBar = {
		  view: function (vnode) {
			const options = vnode.attrs.options || ['min', 'max', 'close']
			const name = vnode.attrs.name || "Window Maker"
			return m("div", { class: "title-bar" }, [
			  m("div", { class: "title-bar-text" }, String(name)),
			  m("div", { class: "title-bar-controls" }, [
				options.includes('min') && m("button", { 'aria-label': 'Minimize' }),
				options.includes('max') && m("button", { 'aria-label': 'Maximize' }),
				options.includes('close') && m("button", { 'aria-label': 'Close' }),
			  ]),
			])
		  }
		}
  
		const WindowBody = {
		  view: function () {
			return m("div", { class: "window-body" }, [
			  m("p", [
				"Do you miss these looks and feels? We can help!",
				m("br"),
				"Window Maker is a website to help people build their own UI in 3 minutes!"
			  ]),
			  m("p", [
				m(InputWindowName),
				m(InputWindowContent),
				m("br"),
				m(InputToolbar),
				m("br"),
				m(InputStatusBar)
			  ]),
			  m("button", {
				onclick: function () {
				  const windowName = document.querySelector('#win-name').value
				  const windowContent = document.querySelector('#win-content').value
				  const toolbar = Array.from(document.querySelectorAll('input[type=checkbox]:checked')).map(item => item.value)
				  const showStatus = document.querySelector('#radio-yes').checked
				  const config = {
					'window-name': windowName,
					'window-content': windowContent,
					'window-toolbar': toolbar,
					'window-statusbar': showStatus
				  }
				  const qs = m.buildQueryString({
					config
				  })
				  window.location.search = '?' + qs
				}
			  }, "generate")
			])
		  }
		}
  
		const InputWindowName = {
		  view: function (vnode) {
			return m("div", { class: "field-row-stacked" }, [
			  m("label", { for: 'win-name' }, 'Window name'),
			  m("input", { id: 'win-name', type: 'text' }),
			])
		  }
		}
  
		const InputWindowContent = {
		  view: function (vnode) {
			return m("div", { class: "field-row-stacked" }, [
			  m("label", { for: 'win-content' }, 'Window content(plaintext only)'),
			  m("textarea", { id: 'win-content', rows: '8' }),
			])
		  }
		}
  
		const InputToolbar = {
		  view: function (vnode) {
			return m("div", [
			  m("div", { class: "field-row" }, [
				m("label", "Toolbar"),
			  ]),
			  m(Checkbox, { id: "toolbar-min", value: "min" }),
			  m(Checkbox, { id: "toolbar-max", value: "max" }),
			  m(Checkbox, { id: "toolbar-close", value: "close" }),
			])
		  }
		}
  
		const Checkbox = {
		  view: function (vnode) {
			return m("div", { class: "field-row" }, [
			  m("input", { id: String(vnode.attrs.id), type: 'checkbox', value: String(vnode.attrs.value) }),
			  m("label", { for: String(vnode.attrs.id) }, String(vnode.attrs.value)),
			])
		  }
		}
  
		const InputStatusBar = {
		  view: function () {
			return m("div", [
			  m("div", { class: "field-row" }, [
				m("label", "Status bar"),
			  ]),
			  m(RadioButton, { id: "radio-yes", value: "Yes" }),
			  m(RadioButton, { id: "radio-no", value: "No" }),
			])
		  }
		}
  
		const RadioButton = {
		  view: function (vnode) {
			return m("div", { class: "field-row" }, [
			  m("input", { id: String(vnode.attrs.id), type: 'radio', name: 'status-radio' }),
			  m("label", { for: String(vnode.attrs.id) }, String(vnode.attrs.value)),
			])
		  }
		}
  
		const StatusBar = {
		  view: function () {
			return m("div", { class: "status-bar" }, [
			  m("p", { class: "status-bar-field" }, "Press F1 for help"),
			  m("p", { class: "status-bar-field" }, "Powered by XP.css and Mithril.js"),
			  m("p", { class: "status-bar-field" }, "CPU Usage: 32%"),
			])
		  }
		}
  
		const CustomizedApp = {
		  view: function (vnode) {
			return m("div", { class: "window" }, [
			  m(TitleBar, { name: vnode.attrs.name, options: vnode.attrs.options }),
			  m("div", { class: "window-body" }, [
				String(vnode.attrs.content)
			  ]),
			  vnode.attrs.status && m(StatusBar)
			])
		  }
		}
  
		function main() {
		  const qs = m.parseQueryString(location.search)
  
		  let appConfig = Object.create(null)
		  appConfig["version"] = 1337
		  appConfig["mode"] = "production"
		  appConfig["window-name"] = "Window"
		  appConfig["window-content"] = "default content"
		  appConfig["window-toolbar"] = ["close"]
		  appConfig["window-statusbar"] = false
		  appConfig["customMode"] = false
  
		  if (qs.config) {
			merge(appConfig, qs.config)
			appConfig["customMode"] = true
		  }
  
		  let devSettings = Object.create(null)
		  devSettings["root"] = document.createElement('main')
		  devSettings["isDebug"] = false
		  devSettings["location"] = 'challenge-0422.intigriti.io'
		  devSettings["isTestHostOrPort"] = false
  
		  if (checkHost()) {
			devSettings["isTestHostOrPort"] = true
			merge(devSettings, qs.settings)
		  }
  
		  if (devSettings["isTestHostOrPort"] || devSettings["isDebug"]) {
			console.log('appConfig', appConfig)
			console.log('devSettings', devSettings)
		  }
  
		  if (!appConfig["customMode"]) {
			m.mount(devSettings.root, App)
		  } else {
			m.mount(devSettings.root, {
			  view: function () {
				return m(CustomizedApp, {
				  name: appConfig["window-name"],
				  content: appConfig["window-content"],
				  options: appConfig["window-toolbar"],
				  status: appConfig["window-statusbar"]
				})
			  }
			})
		  }
  
		  document.body.appendChild(devSettings.root)
		}
  
		function checkHost() {
		  const temp = location.host.split(':')
		  const hostname = temp[0]
		  const port = Number(temp[1]) || 443
		  return hostname === 'localhost' || port === 8080
		}
  
		function isPrimitive(n) {
		  return n === null || n === undefined || typeof n === 'string' || typeof n === 'boolean' || typeof n === 'number'
		}
  
		function merge(target, source) {
		  let protectedKeys = ['__proto__', "mode", "version", "location", "src", "data", "m"]
  
		  for (let key in source) {
			if (protectedKeys.includes(key)) {
			  continue
			}
  
  
			if (isPrimitive(target[key])) {
			  target[key] = sanitize(source[key])
			} else {
			  merge(target[key], source[key])
			}
		  }
		}
		function sanitize(data) {
		  if (typeof data !== 'string') return data
		  return data.replace(/[<>%&\$\s\\]/g, '_').replace(/script/gi, '_')
		}
  
		main()
	  })()

	`
	var params = []string{}
	var vardiscover bool
	o := js.Options{}
	ast, err := js.Parse(parse.NewInputString(jsbody), o)
	if err != nil {
		panic(err.Error())
	}

	// ast.BlockStmt.String()

	// for _, v := range ast.BlockStmt.VarDecls {
	// 	fmt.Println(v.String())
	// }

	fmt.Println("Scope:", ast.Scope.String())
	fmt.Println("Scope Func:", ast.Scope.Func.String())

	fmt.Println("JS:", ast.String())
	//ast.BlockStmt.String()
	l := js.NewLexer(parse.NewInputString(jsbody))
	for {
		tt, text := l.Next()
		fmt.Printf("value %v type %v \n", string(text), tt)

		switch tt {
		case js.ErrorToken:
			if l.Err() != io.EOF {
				fmt.Println("Error on line:", l.Err())
			}
			t.Log("ok")
			break
		case js.VarToken:
			vardiscover = true
		case js.StringToken:
			str := string(text)
			if vardiscover {
				params = append(params, str)
			}
			vardiscover = false
		case js.IdentifierToken:
			// fmt.Println("IdentifierToken", string(text))
		}
	}
}
