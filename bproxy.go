package main

import "github.com/google/martian/v3"

type Proxy struct {
	port int
}

func (p *Proxy) init() error {
	P := martian.NewProxy()
	defer P.Close()
	return nil
}
