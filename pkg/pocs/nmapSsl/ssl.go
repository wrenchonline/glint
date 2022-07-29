package nmapSsl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"log"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v2"
	"github.com/thoas/go-funk"
)

var DefaultProxy = ""

// var cert string
// var mkey string

var threadwg sync.WaitGroup //同步线程

func Sslverify(args interface{}) (*util.ScanResult, bool, error) {
	var Param layers.PluginParam
	ct := layers.CheckType{}
	Param.ParsePluginParams(args.(plugin.GroupData), ct)
	if Param.CheckForExitSignal() {
		return nil, false, errors.New("receive task exit signal")
	}

	// sess := nenet.GetSessionByOptions(
	// 	&nenet.ReqOptions{
	// 		Timeout:       time.Duration(Param.Timeout) * time.Second,
	// 		AllowRedirect: false,
	// 		Proxy:         Param.UpProxy,
	// 		Cert:          Param.Cert,
	// 		PrivateKey:    Param.CertKey,
	// 	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5 minute timeout.
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(Param.Url),
		nmap.WithPorts("443"),
		nmap.WithScripts("ssl-enum-ciphers"),
		nmap.WithContext(ctx),
	)

	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	if warnings != nil {
		log.Printf("Warnings: \n %v", warnings)
	}
	var buf bytes.Buffer

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])
		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
		rawXml := result.ToReader()
		buf.ReadFrom(rawXml)
		fmt.Printf("raw XMl:%s", buf.String())
		if funk.Contains(buf.String(), "TLSv1.0") {
			Result := util.VulnerableTcpOrUdpResult(Param.Url,
				"TLSV0 has enable",
				[]string{string("")},
				[]string{string("")},
				"high",
				Param.Hostid)
			return Result, true, nil
		}
		if funk.Contains(buf.String(), "TLSv1.1") {
			Result := util.VulnerableTcpOrUdpResult(Param.Url,
				"TLSV1 has enable",
				[]string{string("")},
				[]string{string("")},
				"middle",
				Param.Hostid)
			return Result, true, nil
		}
	}
	return nil, false, errors.New("not found")
}
