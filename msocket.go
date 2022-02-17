package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"glint/logger"
	"io"
	"log"
	"net"
	"strconv"
)

type ConnCallback func(ctx context.Context, mjson map[string]interface{}) error

type MConn struct {
	CallbackFunc ConnCallback
	Signal       chan string
}

var SOCKETCONN []*net.Conn

func (m *MConn) Init() error {
	m.Signal = make(chan string)
	return nil
}

func (m *MConn) SendAll(status int, message string, taskid int) error {
	var (
		err error
	)

	reponse := make(map[string]interface{})
	reponse["status"] = status
	reponse["msg"] = message
	reponse["taskid"] = strconv.Itoa(taskid)
	data, err := json.Marshal(reponse)
	bs := make([]byte, len(data)+4)
	//大端通讯
	binary.BigEndian.PutUint32(bs, uint32(len(data)))
	copy(bs[4:], data)
	// logger.Info("%v", reponse)
restart:
	for idx, conn := range SOCKETCONN {
		if err != nil {
			logger.Error(err.Error())
		}
		if len(data) > 0 {
			_, err = (*conn).Write(bs)
			if err != nil {
				logger.Error(err.Error())
				SOCKETCONN = append(SOCKETCONN[:idx], SOCKETCONN[(idx+1):]...)
				goto restart
			}
		}
	}
	return err
}

//此框架我准备设计成一对多的形式模块处理业务，方便自己以后二次开发。
func (m *MConn) handle(ctx context.Context, data []byte) error {
	mjson := make(map[string]interface{})
	err := json.Unmarshal(data, &mjson)
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	err = m.CallbackFunc(ctx, mjson)
	return err
}

func (m *MConn) Listen(con net.Conn) {
	defer con.Close()
	reader := bufio.NewReader(con)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		peek, err := reader.Peek(4)
		if err != nil {
			if err != io.EOF {
				logger.Error(err.Error())
			} else {
				break
			}
		}
		var length uint32
		buffer := bytes.NewBuffer(peek)
		err = binary.Read(buffer, binary.BigEndian, &length)
		if err != nil {
			logger.Error(err.Error())
		}
		if uint32(reader.Buffered()) < length+4 {
			continue
		}
		data := make([]byte, length+4)
		_, err = reader.Read(data)
		if err != nil {
			continue
		}
		log.Println("received msg", string(data[4:]))
		go m.handle(ctx, data[4:])
		buffer.Reset()
	}

}
