package main

import (
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

func DnsServer(addr *net.UDPAddr, conn *net.UDPConn, msg dnsmessage.Message) {
	if len(msg.Questions) < 1 {
		return
	}
	question := msg.Questions[0]
	var (
		//queryTypeStr = question.Type.String()
		queryNameStr = question.Name.String()
		queryType    = question.Type
		queryName, _ = dnsmessage.NewName(queryNameStr)
	)
	//域名过滤，避免网络扫描
	// if strings.Contains(queryNameStr, Core.Config.Dns.Domain) {
	// 	D.Set(DnsInfo{
	// 		Subdomain: queryNameStr[:len(queryNameStr)-1],
	// 		Ipaddress: addr.IP.String(),
	// 		Time:      time.Now().Unix(),
	// 	})
	// } else {
	// 	return
	// }
	var resource dnsmessage.Resource
	switch queryType {
	case dnsmessage.TypeA:
		// resource = NewAResource(queryName, [4]byte{127, 0, 0, 1})
	default:
		//fmt.Printf("not support dns queryType: [%s] \n", queryTypeStr)
		return
	}

	// send response
	msg.Response = true
	msg.Answers = append(msg.Answers, resource)
	// Response(addr, conn, msg)
}
