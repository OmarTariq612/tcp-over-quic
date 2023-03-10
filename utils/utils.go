package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

const (
	PROTO                = "tcp-over-quic"
	GREEN                = "\033[92m"
	ORANGE               = "\033[38;5;214m"
	END                  = "\033[0m"
	TCP_CONNECTION_RESET = 0x00
)

func Pipe(stream quic.Stream, conn io.ReadWriteCloser, streams *int64) {
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, conn)
		if err != nil {
			log.Printf("%s%T%s", ORANGE, err, END)
			if err, ok := err.(*quic.StreamError); ok {
				log.Printf("%scopy: %s%s", ORANGE, err.Error(), END)
			}
		}
		errc <- err
	}()
	go func() {
		_, err := io.Copy(conn, stream)
		if err != nil {
			log.Printf("%s%T%s", ORANGE, err, END)
			if err, ok := err.(*quic.StreamError); ok {
				log.Printf("%scopy: %s%s", ORANGE, err.Error(), END)
			}
		}
		errc <- err
	}()
	log.Print(<-errc)
	stream.CancelRead(TCP_CONNECTION_RESET)
	stream.CancelWrite(TCP_CONNECTION_RESET)
	if err := conn.Close(); err != nil {
		log.Print(fmt.Errorf("conn.Close(): %w", err))
	}
	atomic.AddInt64(streams, -1)
}

type Envelope map[string]any

func WriteJSON(w http.ResponseWriter, status int, data Envelope, headers http.Header) error {
	js, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return err
	}

	js = append(js, '\n')
	for key, value := range headers {
		w.Header()[key] = value
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(js)

	return nil
}
