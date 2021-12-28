package main

import (
	"context"
	"encoding/base64"
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

	// DM
	Dm *dbmanager.DbManager
}

//Tasks 进行的任务
var Tasks []Task

var Taskslock sync.Mutex

var DoStartSignal chan bool

var PliuginsMsg chan map[string]interface{}

type TaskStatus int

const (
	TaskERROR        TaskStatus = -1
	TaskHasCompleted TaskStatus = 0
	TaskHasStart     TaskStatus = 1
)

func quitmsg(ctx context.Context, c *websocket.Conn) {
	<-DoStartSignal
	logger.Info("Monitor the exit signal of the task")
	for _, task := range Tasks {
		<-(*task.Ctx).Done()
		sendmsg(ctx, c, 2, "The Task is End")
	}
}

// NewTaskServer
func NewTaskServer() *TaskServer {
	ts := &TaskServer{
		subscriberMessageBuffer: 16,
		// subscribers:             make(map[*subscriber]struct{}),
		publishLimiter: rate.NewLimiter(rate.Every(time.Millisecond*100), 8),
	}
	ts.serveMux.Handle("/", http.FileServer(http.Dir(".")))
	ts.serveMux.HandleFunc("/task", ts.TaskHandler)
	ts.serveMux.HandleFunc("/publish", ts.PublishHandler)
	ts.Dm = &dbmanager.DbManager{}
	ts.Dm.Init()
	return ts
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
		defer c.Close(websocket.StatusInternalError, "")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		err = ts.Task(ctx, c)
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

func sendmsg(ctx context.Context, c *websocket.Conn, status int, message string) error {
	reponse := make(map[string]interface{})
	reponse["status"] = status
	reponse["msg"] = message
	logger.Info("%v", reponse)
	err := wsjson.Write(ctx, c, reponse)
	return err
}

func (ts *TaskServer) Task(ctx context.Context, c *websocket.Conn) error {
	// ctx = c.CloseRead(ctx)
	DoStartSignal = make(chan bool)
	PliuginsMsg = make(chan map[string]interface{})
	var v interface{}
	var jsonobj interface{}
	for {
		err := wsjson.Read(ctx, c, &v)
		if err != nil {
			logger.Error(err.Error())
			return err
		}
		err = json.Unmarshal([]byte(v.(string)), &jsonobj)
		if err != nil {
			logger.Error(err.Error())
			return err
		}
		json := jsonobj.(map[string]interface{})
		Status := json["action"].(string)
		if strings.ToLower(Status) == "start" {
			status, err := ts.GetTaskStatus(json)
			if err != nil {
				sendmsg(ctx, c, -1, err.Error())
				continue
			}
			if status == TaskHasStart {
				sendmsg(ctx, c, 1, "The Task Has Started")
				continue
			}
			//开始任务
			task, err := ts.start(jsonobj)
			if err != nil {
				sendmsg(ctx, c, -1, err.Error())
				continue
			}
			Taskslock.Lock()
			Tasks = append(Tasks, task)
			Taskslock.Unlock()
			sendmsg(ctx, c, 0, "The Task is Starting")
			go quitmsg(ctx, c)
		} else if strings.ToLower(Status) == "close" {
			if len(Tasks) != 0 {
				for _, task := range Tasks {
					(*task.Cancel)()
				}
				Tasks = nil
			}
		}
	}
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

func PluginMsgHandler(ctx context.Context, c *websocket.Conn) {
	for {
		select {
		case msg := <-PliuginsMsg:
			fmt.Printf("msg: %v\n", msg)
			reponse := make(map[string]interface{})
			reponse["status"] = 0
			reponse["msg"] = msg
			err := wsjson.Write(ctx, c, reponse)
			if err != nil {
				logger.Error(err.Error())
			}
		case <-time.After(time.Second * 1):

		case <-ctx.Done():
			logger.Warning("PluginMsgHandler exit ...")
			return
		}
	}
}
