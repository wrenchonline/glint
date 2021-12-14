package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"glint/dbmanager"
	"glint/log"
	"io/ioutil"
	"net/http"
	"strings"
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

	//Tasks 进行的任务
	Tasks []Task
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
		log.Error(err.Error())
		return
	}
	defer c.Close(websocket.StatusInternalError, "")

	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()
	err = ts.Task(ctx, c)
	if errors.Is(err, context.Canceled) {
		log.Error(err.Error())
		return
	}
	if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
		websocket.CloseStatus(err) == websocket.StatusGoingAway {
		log.Error(err.Error())
		return
	}
	if err != nil {
		log.Error(err.Error())
		return
	}
}

func (ts *TaskServer) Task(ctx context.Context, c *websocket.Conn) error {
	// ctx = c.CloseRead(ctx)
	var v interface{}
	var jsonobj interface{}
	for {
		err := wsjson.Read(ctx, c, &v)
		if err != nil {
			return err
		}
		err = json.Unmarshal([]byte(v.(string)), &jsonobj)
		if err != nil {
			return err
		}
		json := v.(map[string]interface{})
		Status := json["status"].(string)
		if strings.ToLower(Status) == "start" {
			task, err := ts.start(jsonobj)
			if err != nil {
				log.Error(err.Error())
			}
			ts.Tasks = append(ts.Tasks, task)
			go func() {
				task.PluginWg.Wait()

			}()
			//
		} else if strings.ToLower(Status) == "close" {

		}
	}
}

func (ts *TaskServer) start(v interface{}) (Task, error) {
	// var response interface{}
	var task Task

	json := v.(map[string]interface{})
	log.Debug("%v", json)

	task.TaskId = json["taskid"].(int)

	DBTaskConfig, err := ts.Dm.GetTaskConfig(task.TaskId)
	if err != nil {
		log.Error(err.Error())
	}
	TaskConfig, err := ts.Dm.ConvertDbTaskConfigToJson(DBTaskConfig)
	if err != nil {
		log.Error(err.Error())
	}
	task.Init()
	task.TaskConfig = TaskConfig
	urls := strings.Split(DBTaskConfig.Urls.String, "|")
	for _, url := range urls {
		task.UrlPackage(url)
	}
	task.dostartTasks(true)

	return task, nil
}

func writeTimeout(ctx context.Context, timeout time.Duration, c *websocket.Conn, msg interface{}) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return wsjson.Write(ctx, c, msg)
}

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
		log.Error(err.Error())
	}

	w.WriteHeader(http.StatusOK)
}
