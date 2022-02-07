package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
)

type ConnCallback func(args interface{}) error

type MConn struct {
	CallbackFunc ConnCallback
	Signal       chan string
	SOCKETCONN   []*net.Conn
}

func (m *MConn) Init() error {
	m.Signal = make(chan string)
	return nil
}

//此框架我准备设计成一对多的形式模块处理业务，方便自己以后二次开发。

func (m *MConn) handle(data []byte) {
	m.CallbackFunc(data)
}

func (m *MConn) listeningSocket(con net.Conn) {

	defer con.Close()
	reader := bufio.NewReader(con)
	for {
		peek, err := reader.Peek(4)
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			} else {
				break
			}
		}
		buffer := bytes.NewBuffer(peek)
		var length int32
		err = binary.Read(buffer, binary.BigEndian, &length)
		if err != nil {
			log.Println(err)
		}
		if int32(reader.Buffered()) < length+4 {
			continue
		}
		data := make([]byte, length+4)
		_, err = reader.Read(data)
		if err != nil {
			continue
		}
		log.Println("received msg", string(data[4:]))
	}

}

func Start() {

	var m MConn
	m.Init()

	listener, err := net.Listen("tcp", "127.0.0.1:3010")
	defer listener.Close()
	if err != nil {
		log.Fatal(err)
	}

	for {
		con, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go m.listeningSocket(con)
		m.SOCKETCONN = append(m.SOCKETCONN, &con)
	}
}
