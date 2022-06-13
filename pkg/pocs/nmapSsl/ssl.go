package nmapSsl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"glint/plugin"
	"glint/util"
	"log"
	"time"

	"github.com/Ullaakut/nmap/v2"
	"github.com/thoas/go-funk"
)

var DefaultProxy = ""

// var cert string
// var mkey string

func Sslverify(args interface{}) (*util.ScanResult, error) {
	util.Setup()
	var hostid int64

	group := args.(plugin.GroupData)
	// ORIGIN_URL := `http://not-a-valid-origin.xsrfprobe-csrftesting.0xinfection.xyz`
	ctx := *group.Pctx

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	session := group.GroupUrls.(map[string]interface{})
	url := session["url"].(string)
	// method := session["method"].(string)
	// headers, _ := util.ConvertHeaders(session["headers"].(map[string]interface{}))
	// body := []byte(session["data"].(string))
	// cert = group.HttpsCert
	// mkey = group.HttpsCertKey
	// sess := fastreq.GetSessionByOptions(
	// 	&fastreq.ReqOptions{
	// 		Timeout:       2 * time.Second,
	// 		AllowRedirect: true,
	// 		Proxy:         DefaultProxy,
	// 		Cert:          cert,
	// 		PrivateKey:    mkey,
	// 	})
	if value, ok := session["hostid"].(int64); ok {
		hostid = value
	}

	if value, ok := session["hostid"].(json.Number); ok {
		hostid, _ = value.Int64()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5 minute timeout.
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(url),
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
			Result := util.VulnerableTcpOrUdpResult(url,
				"TLSV0 has enable",
				[]string{string("")},
				[]string{string("")},
				"high",
				hostid)
			return Result, nil
		}
		if funk.Contains(buf.String(), "TLSv1.1") {
			Result := util.VulnerableTcpOrUdpResult(url,
				"TLSV1 has enable",
				[]string{string("")},
				[]string{string("")},
				"middle",
				hostid)
			return Result, nil
		}
	}
	return nil, errors.New("not found")
}
