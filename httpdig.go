package httpdig

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var apiURL = "https://dns.google.com/resolve"
var ednsSubnet = "0.0.0.0/0"

// Response from Google's DNS resolver
type Response struct {
	Status int  `json:"Status"`
	TC     bool `json:"TC"`
	RD     bool `json:"RD"`
	RA     bool `json:"RA"`
	AD     bool `json:"AD"`
	CD     bool `json:"CD"`

	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`

	Answer []struct {
		Name string        `json:"name"`
		Type int           `json:"type"`
		TTL  time.Duration `json:"TTL"`
		Data string        `json:"data"`
	} `json:"Answer"`

	Authority []struct {
		Name string        `json:"name"`
		Type int           `json:"type"`
		TTL  time.Duration `json:"TTL"`
		Data string        `json:"data"`
	} `json:"Authority"`

	Additional       []interface{} `json:"Additional"`
	EdnsClientSubnet string        `json:"edns_client_subnet"`
	Comment          string        `json:"Comment"`
}

func dig(host, recordType string) ([]byte, error) {
	client := &http.Client{}

	req, _ := http.NewRequest("GET", apiURL, nil)

	query := req.URL.Query()
	query.Add("name", host)
	query.Add("type", recordType)
	if len(ednsSubnet) > 0 { // while the default is to be anonymous, it's possible to unset this value via SetEDNSSubnet
		query.Add("edns_client_subnet", ednsSubnet)
	}
	query.Add("random_padding", strings.Repeat("0", 253-len(host))) // pad domain name to 253 chars, effectively, to reduce a potential length-based side-channel attack/leak.

	req.URL.RawQuery = query.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, errors.New("Unable to resolve host")
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	return body, nil
}

// Query sends request to Google dns service and parses response.
// e.g: httpdig.Query("google.com", "NS")
func Query(host string, t string) (Response, error) {
	resp, err := dig(host, t)
	if err != nil {
		return Response{}, err
	}

	response := Response{}
	err = json.Unmarshal(resp, &response)

	// scale TTL fields to seconds of duration instead of ns
	for i := range response.Answer {
		response.Answer[i].TTL *= time.Second
	}
	for i := range response.Authority {
		response.Authority[i].TTL *= time.Second
	}

	if err != nil {
		return Response{}, err
	}

	return response, nil
}

// SetEDNSSubnet sets the EDNS-CLIENT-SUBNET value for a potentially geolocation optimized response.
// By default, this is "0.0.0.0/0" for better anonymity, as it would be easy for this feature to be abused by anyone in the lookup path.
// If you set it to "", it will permit Google to use your apparent public IP address (with the last portion chopped off).
// The format needs to be in slashed-subnet format, such as "127.1.2.3/24".
func SetEDNSSubnet(subnet string) {
	ednsSubnet = subnet
}
