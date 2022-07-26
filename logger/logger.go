package logger

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/logrusorgru/aurora"
)

var stdout io.Writer = color.Output
var g_rl *readline.Instance = nil
var debug_output = true
var mtx_log *sync.Mutex = &sync.Mutex{}
var au aurora.Aurora

const (
	DEBUG = iota
	INFO
	IMPORTANT
	WARNING
	ERROR
	FATAL
	SUCCESS
)

var LogLabels = map[int]string{
	DEBUG:     "dbg",
	INFO:      "inf",
	IMPORTANT: "imp",
	WARNING:   "war",
	ERROR:     "err",
	FATAL:     "!!!",
	SUCCESS:   "+++",
}

func DebugEnable(enable bool) {
	debug_output = enable
}

func SetOutput(o io.Writer) {
	stdout = o
}

func SetReadline(rl *readline.Instance) {
	g_rl = rl
}

func GetOutput() io.Writer {
	return stdout
}

func NullLogger() *log.Logger {
	return log.New(ioutil.Discard, "", 0)
}

func refreshReadline() {
	if g_rl != nil {
		g_rl.Refresh()
	}
}

func Debug(format string, args ...interface{}) {
	mtx_log.Lock()
	defer mtx_log.Unlock()

	if debug_output {
		fmt.Fprint(stdout, format_msg(DEBUG, format+"\n", args...))
		refreshReadline()
	}
}

func Info(format string, args ...interface{}) {
	mtx_log.Lock()
	defer mtx_log.Unlock()

	fmt.Fprint(stdout, format_msg(INFO, format+"\n", args...))
	refreshReadline()
}

func Important(format string, args ...interface{}) {
	mtx_log.Lock()
	defer mtx_log.Unlock()

	fmt.Fprint(stdout, format_msg(IMPORTANT, format+"\n", args...))
	refreshReadline()
}

func Warning(format string, args ...interface{}) {
	mtx_log.Lock()
	defer mtx_log.Unlock()

	fmt.Fprint(stdout, format_msg(WARNING, format+"\n", args...))
	refreshReadline()
}

func Error(format string, args ...interface{}) {
	mtx_log.Lock()
	defer mtx_log.Unlock()

	fmt.Fprint(stdout, format_msg(ERROR, format+"\n", args...))
	refreshReadline()
}

func Fatal(format string, args ...interface{}) {
	mtx_log.Lock()
	defer mtx_log.Unlock()

	fmt.Fprint(stdout, format_msg(FATAL, format+"\n", args...))
	refreshReadline()
}

func Success(format string, args ...interface{}) {
	mtx_log.Lock()
	defer mtx_log.Unlock()

	fmt.Fprint(stdout, format_msg(SUCCESS, format+"\n", args...))
	refreshReadline()
}

func Printf(format string, args ...interface{}) {
	mtx_log.Lock()
	defer mtx_log.Unlock()

	fmt.Fprintf(stdout, format, args...)
	refreshReadline()
}

// 获取正在运行的函数名
func RunFuncName() string {
	pc := make([]uintptr, 1)
	runtime.Callers(4, pc)
	f := runtime.FuncForPC(pc[0])
	return f.Name()
}

func format_msg(lvl int, format string, args ...interface{}) string {
	var msg string
	var time_clr string
	var sign string
	var func_name string
	t := time.Now()

	switch lvl {
	case DEBUG:
		msg = aurora.Sprintf(aurora.Cyan(format), args...)
		time_clr = aurora.Sprintf(aurora.Cyan("\r[%02d:%02d:%02d]"), t.Hour(), t.Minute(), t.Second())
		sign = aurora.Sprintf(aurora.Cyan("[%s]"), LogLabels[lvl])
		func_name = aurora.Sprintf(aurora.Cyan("[%s]"), RunFuncName())
	case INFO:
		msg = aurora.Sprintf(aurora.Magenta(format), args...)
		time_clr = aurora.Sprintf(aurora.Magenta("\r[%02d:%02d:%02d]"), t.Hour(), t.Minute(), t.Second())
		sign = aurora.Sprintf(aurora.Magenta("[%s]"), LogLabels[lvl])
		func_name = aurora.Sprintf(aurora.Magenta("[%s]"), RunFuncName())
	case IMPORTANT:
		msg = aurora.Sprintf(aurora.Brown(format), args...)
		time_clr = aurora.Sprintf(aurora.Brown("\r[%02d:%02d:%02d]"), t.Hour(), t.Minute(), t.Second())
		sign = aurora.Sprintf(aurora.Brown("[%s]"), LogLabels[lvl])
		func_name = aurora.Sprintf(aurora.Brown("[%s]"), RunFuncName())
	case WARNING:
		msg = aurora.Sprintf(aurora.Yellow(format), args...)
		time_clr = aurora.Sprintf(aurora.Yellow("\r[%02d:%02d:%02d]"), t.Hour(), t.Minute(), t.Second())
		sign = aurora.Sprintf(aurora.Yellow("[%s]"), LogLabels[lvl])
		func_name = aurora.Sprintf(aurora.Yellow("[%s]"), RunFuncName()+"::")
	case ERROR:
		msg = aurora.Sprintf(aurora.Red(format), args...)
		time_clr = aurora.Sprintf(aurora.Red("\r[%02d:%02d:%02d]"), t.Hour(), t.Minute(), t.Second())
		sign = aurora.Sprintf(aurora.Red("[%s]"), LogLabels[lvl])
		func_name = aurora.Sprintf(aurora.Red("[%s]"), RunFuncName())
	case FATAL:
		msg = aurora.Sprintf(aurora.Red(format), args...)
		time_clr = aurora.Sprintf(aurora.Red("\r[%02d:%02d:%02d]"), t.Hour(), t.Minute(), t.Second())
		sign = aurora.Sprintf(aurora.Red("[%s]"), LogLabels[lvl])
		func_name = aurora.Sprintf(aurora.Red("[%s]"), RunFuncName())
	case SUCCESS:
		msg = aurora.Sprintf(aurora.Green(format), args...)
		time_clr = aurora.Sprintf(aurora.Green("\r[%02d:%02d:%02d]"), t.Hour(), t.Minute(), t.Second())
		sign = aurora.Sprintf(aurora.Green("[%s]"), LogLabels[lvl])
		func_name = aurora.Sprintf(aurora.Green("[%s]::"), RunFuncName())
	}

	return time_clr + sign + func_name + msg
}
