package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"glint/dbmanager"
	"glint/logger"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thoas/go-funk"
	"golang.org/x/time/rate"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

type TaskServer struct {
	// subscriberMessageBuffer controls the max number
	// of messages that can be queued for a subscriber
	// before it is kicked.
	//
	// Defaults to 16.
	subscriberMessageBuffer int

	// publishLimiter controls the rate limit applied to the publish endpoint.
	//
	// Defaults to one publish every 100ms with a burst of 8.
	publishLimiter *rate.Limiter

	// serveMux routes the various endpoints to the appropriate handler.
	serveMux http.ServeMux

	server_type string

	// DM
	Dm *dbmanager.DbManager
}

//Tasks 进行的任务
var Tasks []Task

type soketinfo struct {
	Conn *websocket.Conn
	Ctx  context.Context
}

var Socketinfo []*soketinfo

var Taskslock sync.Mutex

var ServerType string

type TaskStatus int

const (
	TaskERROR        TaskStatus = -1
	TaskHasCompleted TaskStatus = 0
	TaskHasStart     TaskStatus = 1
)

func (t *Task) quitmsg() {
	<-t.DoStartSignal
	logger.Info("Monitor the exit signal of the task")
	for _, task := range Tasks {
		<-(*task.Ctx).Done()
		sendmsg(2, "The Task is End", t.TaskId)
	}
}

// NewTaskServer
func NewTaskServer(server_type string) (*TaskServer, error) {
	ts := &TaskServer{
		subscriberMessageBuffer: 16,
		// subscribers:             make(map[*subscriber]struct{}),
		publishLimiter: rate.NewLimiter(rate.Every(time.Millisecond*100), 8),
	}
	if strings.ToLower(server_type) == "websocket" {
		ts.serveMux.Handle("/", http.FileServer(http.Dir(".")))
		ts.serveMux.HandleFunc("/task", ts.TaskHandler)
		ts.serveMux.HandleFunc("/publish", ts.PublishHandler)
	}

	ts.Dm = &dbmanager.DbManager{}
	ts.server_type = server_type
	ServerType = ts.server_type
	err := ts.Dm.Init()
	if err != nil {
		return nil, err
	}
	return ts, nil

}

func (ts *TaskServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ts.serveMux.ServeHTTP(w, r)
}

// TaskHandler 任务处理
func (ts *TaskServer) TaskHandler(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		logger.Error(err.Error())
		return
	}

	go func() {
		var (
			err     error
			v       interface{}
			jsonobj interface{}
		)

		mjson := make(map[string]interface{})

		defer c.Close(websocket.StatusInternalError, "")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		info := soketinfo{Conn: c, Ctx: ctx}
		Socketinfo = append(Socketinfo, &info)

		for {
			err := wsjson.Read(ctx, c, &v)
			if err != nil {
				logger.Warning(err.Error())
				break
			}
			if value, ok := v.(string); ok {
				err = json.Unmarshal([]byte(value), &jsonobj)
				if err != nil {
					logger.Error(err.Error())
					break
				}
				mjson = jsonobj.(map[string]interface{})
			} else if value, ok := v.((map[string]interface{})); ok {
				for k, v := range value {
					mjson[k] = v
				}
			}
			err = ts.Task(ctx, mjson)
			if err != nil {
				logger.Error(err.Error())
				continue
			}
		}

		if errors.Is(err, context.Canceled) {
			logger.Error(err.Error())
			return
		}
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
			websocket.CloseStatus(err) == websocket.StatusGoingAway {
			logger.Error(err.Error())
			return
		}
		if err != nil {
			logger.Error(err.Error())
			return
		}
	}()
}

func sendmsg(status int, message interface{}, taskid int) error {
	var err error
	reponse := make(map[string]interface{})
	reponse["status"] = status
	reponse["msg"] = message
	reponse["taskid"] = strconv.Itoa(taskid)
	// logger.Info("%v", reponse)
	if ServerType == "websocket" {
	restart:
		for idx, info := range Socketinfo {
			if _, ok := info.Ctx.Deadline(); ok {
				Socketinfo = append(Socketinfo[:idx], Socketinfo[(idx+1):]...)
				goto restart
			} else {
				err = wsjson.Write(info.Ctx, info.Conn, reponse)
			}
		}
	} else {
		data, err := json.Marshal(reponse)
		bs := make([]byte, len(data)+4)
		//大端通讯
		binary.BigEndian.PutUint32(bs, uint32(len(data)+4))
		copy(bs[4:], data)
		logger.Info("sendmsg: %v", reponse)
	restart1:
		for idx, conn := range SOCKETCONN {
			if err != nil {
				logger.Error(err.Error())
			}
			if len(data) > 0 {
				_, err = (*conn).Write(bs)
				if err != nil {
					logger.Error(err.Error())
					SOCKETCONN = append(SOCKETCONN[:idx], SOCKETCONN[(idx+1):]...)
					goto restart1
				}
			}
		}
	}

	return err
}

func (ts *TaskServer) Task(ctx context.Context, mjson map[string]interface{}) error {

	var (
		err    error
		Status string
		taskid string
	)

	if mjson == nil {
		return err
	}

	if value, ok := mjson["action"].(string); ok {
		Status = value
	} else {
		sendmsg(-1, "error: unkown action for the json", 65535)
		return err
	}
	if value, ok := mjson["taskid"].(string); ok {
		taskid = value
	} else {
		sendmsg(-1, "error: unkown taskid for the json", 65535)
		return err
	}

	id, err := strconv.Atoi(taskid)
	if err != nil {
		panic(err)
	}

	if strings.ToLower(Status) == "start" {
		status, err := ts.GetTaskStatus(mjson)
		if err != nil {
			sendmsg(-1, err.Error(), id)
			return err
		}
		if status == TaskHasStart {
			sendmsg(1, "The Task Has Started", id)
			return err
		}
		//开始任务
		task, err := ts.start(mjson)
		if err != nil {
			sendmsg(-1, err.Error(), task.TaskId)
			return err
		}
		Taskslock.Lock()
		Tasks = append(Tasks, task)
		Taskslock.Unlock()
		sendmsg(0, "The Task is Starting", task.TaskId)
		go task.PluginMsgHandler(*task.Ctx)
		go task.quitmsg()
	} else if strings.ToLower(Status) == "close" {
		if len(Tasks) != 0 {
			for _, task := range Tasks {
				(*task.Cancel)()
			}
			Tasks = nil
		}
	}
	return err
}

func (ts *TaskServer) GetTaskStatus(json map[string]interface{}) (TaskStatus, error) {
	if len(Tasks) != 0 {
		for _, task := range Tasks {
			taskid, err := GetTaskId(json)
			if err != nil {
				return TaskERROR, err
			}
			if task.TaskId == taskid {
				return TaskHasStart, nil
			}
		}
	}
	return TaskHasCompleted, nil
}

func GetTaskId(json map[string]interface{}) (int, error) {
	var taskid int
	if v, ok := json["taskid"].(string); ok {
		id, _ := strconv.Atoi(v)
		taskid = int(id)
	} else if v, ok := json["taskid"].(float64); ok {
		taskid = int(v)
	} else {
		return 0, errors.New("no parse for taskid type")
	}
	return taskid, nil
}

func (ts *TaskServer) start(v interface{}) (Task, error) {
	var task Task
	var Err error
	json := v.(map[string]interface{})
	// logger.DebugEnable(true)
	logger.Debug("%v", json)

	task.TaskId, Err = GetTaskId(json)
	task.Dm = ts.Dm

	if Err != nil {
		logger.Error(Err.Error())
	}
	DBTaskConfig, Err := ts.Dm.GetTaskConfig(task.TaskId)
	if Err != nil {
		logger.Error(Err.Error())
	}
	TaskConfig, Err := ts.Dm.ConvertDbTaskConfigToJson(DBTaskConfig)
	if Err != nil {
		logger.Error(Err.Error())
	}
	task.Init()
	task.TaskConfig = TaskConfig
	urls := strings.Split(DBTaskConfig.Urls.String, "|")
	for _, url := range urls {
		Err = task.UrlPackage(url)
		if Err != nil {
			return task, Err
		}
	}
	go task.dostartTasks(true)
	return task, Err
}

// func writeTimeout(ctx context.Context, timeout time.Duration, c *websocket.Conn, msg interface{}) error {
// 	ctx, cancel := context.WithTimeout(ctx, timeout)
// 	defer cancel()
// 	return wsjson.Write(ctx, c, msg)
// }

//PublishHandler 这个专门记录反链记录
func (ts *TaskServer) PublishHandler(w http.ResponseWriter, r *http.Request) {
	id := string(funk.RandomString(11, []rune("0123456789")))
	Host := r.Host
	Method := r.Method
	body := http.MaxBytesReader(w, r.Body, 8192)
	msg, err := ioutil.ReadAll(body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}
	Data := msg
	User_Agent := r.Header.Get("User-Agent")
	Content_Type := r.Header.Get("Content-Type")
	Created_Time := time.Now().Local()

	State := dbmanager.PublishState{
		Id:          dbmanager.NewNullString(id),
		Host:        dbmanager.NewNullString(Host),
		Method:      dbmanager.NewNullString(Method),
		Data:        dbmanager.NewNullString(base64.RawStdEncoding.EncodeToString(Data)),
		UserAgent:   dbmanager.NewNullString(User_Agent),
		ContentType: dbmanager.NewNullString(Content_Type),
		CreatedTime: Created_Time,
	}

	err = ts.Dm.InstallHttpsReqStatus(&State)
	if err != nil {
		logger.Error(err.Error())
	}

	w.WriteHeader(http.StatusOK)
}

func (t *Task) PluginMsgHandler(ctx context.Context) {
	// var err error
	for {
		select {
		case msg := <-t.PliuginsMsg:
			fmt.Printf("msg: %v\n", msg)
			// reponse := make(map[string]interface{})
			// reponse["status"] = msg["status"].(int)
			// reponse["msg"] = msg
			// reponse["taskid"] = strconv.Itoa(t.TaskId)
			status := msg["status"].(int)
			sendmsg(status, msg, t.TaskId)

		// restart:
		// 	for idx, info := range Socketinfo {
		// 		if _, ok := info.Ctx.Deadline(); ok {
		// 			Socketinfo = append(Socketinfo[:idx], Socketinfo[(idx+1):]...)
		// 			goto restart
		// 		} else {
		// 			err = wsjson.Write(info.Ctx, info.Conn, reponse)
		// 		}
		// 	}
		// 	if err != nil {
		// 		logger.Error(err.Error())
		// 	}
		// case <-time.After(time.Millisecond * 500):
		case <-ctx.Done():
			logger.Warning("PluginMsgHandler exit ...")
			return
		}
	}
}
