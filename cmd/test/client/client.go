package main

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/exp/slog"
)

const (
	path = "/ping"
	arg  = "msg"

	envServerURL     = "SERVER_URL"
	defaultServerURL = "http://localhost:8080"

	sleepTime = time.Second
)

var words = strings.Split("In a village of La Mancha, the name of which I have no desire to call to mind", " ")

func main() {
	serverURL := defaultServerURL
	if ps, ok := os.LookupEnv(envServerURL); ok {
		serverURL = ps
	}
	http.DefaultTransport.(*http.Transport).DisableKeepAlives = true

	for {
		doPing(serverURL, "")
		time.Sleep(sleepTime)
		for _, w := range words {
			doPing(serverURL, w)
			time.Sleep(sleepTime)
		}
	}
}

func doPing(serverURL, word string) {
	url := serverURL + path
	if word != "" {
		url += "?" + arg + "=" + word
	}
	resp, err := http.Get(url)
	if err != nil {
		slog.Error("sending ping", err, "query", url)
		return
	}
	if resp.StatusCode != http.StatusOK {
		slog.Warn("unexpected return", "code", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("reading response body", err)
		return
	}
	slog.Info("server returned", "return", body)
}
