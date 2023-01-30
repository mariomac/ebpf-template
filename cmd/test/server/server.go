package main

import (
	"fmt"
	"golang.org/x/exp/slog"
	"net/http"
	"os"
	"strconv"
)

const (
	path        = "/ping"
	arg         = "msg"
	envPort     = "SERVER_PORT"
	defaultPort = 8080
)

func pingHandler(rw http.ResponseWriter, req *http.Request) {
	slog.Info("connection established", "remoteAddr", req.RemoteAddr)
	if req.URL.Path != path {
		slog.Info("not found", "url", req.URL)
		rw.WriteHeader(http.StatusNotFound)
		return
	}
	ret := "PONG!"
	if req.URL.Query().Has(arg) {
		ret = req.URL.Query().Get(arg)
	}
	rw.WriteHeader(http.StatusOK)
	b, err := rw.Write([]byte(ret))
	if err != nil {
		slog.Error("writing response", err, "url", req.URL)
		return
	}
	slog.Info("written response", "url", req.URL, slog.Int("bytes", b))
	return
}

func main() {
	port := defaultPort
	if ps, ok := os.LookupEnv(envPort); ok {
		var err error
		if port, err = strconv.Atoi(ps); err != nil {
			slog.Error("parsing port", err, "value", ps)
			os.Exit(-1)
		}
	}
	slog.Info("listening and serving", "port", port)
	panic(http.ListenAndServe(fmt.Sprintf(":%d", port), http.HandlerFunc(pingHandler)))
}
