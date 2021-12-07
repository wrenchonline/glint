package main

import (
	"context"
	"encoding/json"
	"errors"
	"glint/log"
	"net/http"
	"time"

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
		repmsgs, err := start(jsonobj)
		if err != nil {
			return errors.Unwrap(err)
		}
		writeTimeout(ctx, time.Second*5, c, repmsgs)
	}
}

func start(v interface{}) (interface{}, error) {
	var response interface{}
	json := v.(map[string]interface{})
	log.Debug("%v", json)
	//获取数据库json
	response = v
	return response, nil
}

func writeTimeout(ctx context.Context, timeout time.Duration, c *websocket.Conn, msg interface{}) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return wsjson.Write(ctx, c, msg)
}
