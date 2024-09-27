package control

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)
const (
	OBLIVIOUS_DOH_CONTENT_TYPE = "application/oblivious-dns-message"
	ODOH_CONFIG_WELLKNOWN_PATH = "/.well-known/odohconfigs"
	ODOH_DEFAULT_PATH          = "/dns-query"
	ODOH_PROXY_DEFAULT_PATH    = "/proxy"
)

func fetchTargetConfigsFromWellKnown(client *http.Client, url string) (odoh.ObliviousDoHConfigs, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}

	return odoh.UnmarshalObliviousDoHConfigs(bodyBytes)
}

func fetchTargetConfigs(client http.Client, targetName string) (odoh.ObliviousDoHConfigs, error) {
	url := url.URL{
		Scheme: "https",
		Host:  targetName,
		Path: ODOH_CONFIG_WELLKNOWN_PATH,
	}
	return fetchTargetConfigsFromWellKnown(&client, url.String())
}

func parseDnsResponse(data []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(data)
	return msg, err
}

func createOdohQuestion(dnsMessage []byte, publicKey odoh.ObliviousDoHConfigContents) (odoh.ObliviousDNSMessage, odoh.QueryContext, error) {
	odohQuery := odoh.CreateObliviousDNSQuery(dnsMessage, 0)
	odnsMessage, queryContext, err := publicKey.EncryptQuery(odohQuery)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, odoh.QueryContext{}, err
	}

	return odnsMessage, queryContext, nil
}

func buildURL(s, defaultPath string) *url.URL {
	s = "https://" + s
	u, err := url.Parse(s)
	if err != nil {
		log.Fatalf("failed to parse url: %v", err)
	}
	if u.Path == "" {
		u.Path = defaultPath
	}
	return u
}

func buildOdohTargetURL(s string) *url.URL {
	return buildURL(s, ODOH_DEFAULT_PATH)
}

func buildOdohProxyURL(proxy, target string) *url.URL {
	p := buildURL(proxy, ODOH_PROXY_DEFAULT_PATH)
	t := buildOdohTargetURL(target)
	qry := p.Query()
	if qry.Get("targethost") == "" {
		qry.Set("targethost", t.Host)
	}
	if qry.Get("targetpath") == "" {
		qry.Set("targetpath", t.Path)
	}
	p.RawQuery = qry.Encode()
	return p
}

func sendODoHRequest(client *http.Client, dnsMessage []byte, odohConfig odoh.ObliviousDoHConfigs, useproxy bool, targetName string, proxy string, proxyHost string) (*dns.Msg, error) {
	config := odohConfig.Configs[0]
	
	odohQuery, queryContext, err := createOdohQuestion(dnsMessage, config.Contents)
	if err != nil {
		return nil, err
	}

	odohMessage, err := resolveObliviousQuery(odohQuery, useproxy, targetName, proxy, proxyHost, client)
	if err != nil {
		fmt.Println("resolve failed", err)
		return nil, err
	}

	dnsResponse, err := validateEncryptedResponse(odohMessage, queryContext)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return dnsResponse, nil
}

func validateEncryptedResponse(message odoh.ObliviousDNSMessage, queryContext odoh.QueryContext) (response *dns.Msg, err error) {
	decryptedResponse, err := queryContext.OpenAnswer(message)
	if err != nil {
		return nil, err
	}

	dnsBytes, err := parseDnsResponse(decryptedResponse)
	if err != nil {
		return nil, err
	}

	return dnsBytes, nil
}

func resolveObliviousQuery(query odoh.ObliviousDNSMessage, useProxy bool, targetIP string, proxy string, proxyHost string, client *http.Client) (response odoh.ObliviousDNSMessage, err error) {
	serializedQuery := query.Marshal()
	req, err := prepareHttpRequest(serializedQuery, useProxy, targetIP, proxy)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}
	req.Host = proxyHost

	fmt.Println("ahhhh222", req.URL.String())
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		fmt.Println("ahhhh222", "redirect")
		return http.ErrUseLastResponse
    }
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("ahhhh222", err)
		fmt.Println("ahhhh222", req.URL.String())
		fmt.Println("ahhhh222", resp.Request.URL.String())
		return odoh.ObliviousDNSMessage{}, err
	}

	responseHeader := resp.Header.Get("Content-Type")
	bodyBytes, err := io.ReadAll(resp.Body)
	fmt.Println(responseHeader)

	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}
	if responseHeader != OBLIVIOUS_DOH_CONTENT_TYPE {
		return odoh.ObliviousDNSMessage{}, fmt.Errorf("did not obtain the correct headers from %v with response %v", targetIP, string(bodyBytes))
	}

	odohQueryResponse, err := odoh.UnmarshalDNSMessage(bodyBytes)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}

	return odohQueryResponse, nil
}

func prepareHttpRequest(serializedBody []byte, useProxy bool, target string, proxy string) (req *http.Request, err error) {
	var u *url.URL
	if useProxy {
		u = buildOdohProxyURL(proxy, target)
	} else {
		u = buildOdohTargetURL(target)
	}
	fmt.Println("ahhh", u.String())
	req, err = http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(serializedBody))
	fmt.Println("url", req.URL.String())

	req.Header.Set("Content-Type", OBLIVIOUS_DOH_CONTENT_TYPE)
	req.Header.Set("Accept", OBLIVIOUS_DOH_CONTENT_TYPE)

	return req, err
}