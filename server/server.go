package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/OmarTariq612/tcp-over-quic/utils"
	"github.com/quic-go/quic-go"
)

type Server struct {
	Certificate    tls.Certificate
	QUICSourceAddr string
	streams        int64
}

func (s *Server) Serve() {
	http.HandleFunc("/server", func(w http.ResponseWriter, r *http.Request) {
		utils.WriteJSON(w, http.StatusOK, utils.Envelope{"streams": s.streams}, nil)
	})

	go http.ListenAndServe(":8888", nil)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{s.Certificate},
		NextProtos:   []string{utils.PROTO},
		MinVersion:   tls.VersionTLS13,
	}

	quicListener, err := quic.ListenAddr(s.QUICSourceAddr, tlsConfig, &quic.Config{MaxIdleTimeout: 24 * time.Hour, MaxIncomingStreams: 10_000_000})
	if err != nil {
		log.Fatalln(fmt.Errorf("listenAddr: %w", err))
	}

	log.Printf("%s[QUIC]%s Listening on %s", utils.ORANGE, utils.END, s.QUICSourceAddr)

	for {
		conn, err := quicListener.Accept(context.Background())
		if err != nil {
			log.Print(fmt.Errorf("accept: %w", err))
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Print(fmt.Errorf("acceptStream: %w", err))
			continue
		}
		atomic.AddInt64(&s.streams, 1)

		go s.handleTCPTunneling(stream)
	}
}

func (s *Server) handleTCPTunneling(stream quic.Stream) {
	defer func() {
		stream.CancelRead(utils.TCP_CONNECTION_RESET)
		stream.CancelWrite(utils.TCP_CONNECTION_RESET)
	}()

	var tlvTypeByte [1]byte
	if _, err := io.ReadFull(stream, tlvTypeByte[:]); err != nil {
		log.Print(fmt.Errorf("io.ReadFull: %w", err))
		atomic.AddInt64(&s.streams, -1)
		return
	}
	tlvType := tlvTypeByte[0]
	if tlvType != 0x00 {
		log.Printf("expecting tcp connect tlv (found: %d)", tlvType)
		atomic.AddInt64(&s.streams, -1)
		return
	}

	var tcpConnectTLVData [19]byte
	if _, err := io.ReadFull(stream, tcpConnectTLVData[:]); err != nil {
		log.Print(fmt.Errorf("io.ReadFull (2): %w", err))
		atomic.AddInt64(&s.streams, -1)
		return
	}

	if _, err := io.ReadFull(stream, tlvTypeByte[:]); err != nil {
		log.Print(fmt.Errorf("io.ReadFull (3): %w", err))
		atomic.AddInt64(&s.streams, -1)
		return
	}

	tlvType = tlvTypeByte[0]
	if tlvType != 0xFF {
		log.Printf("expecting end tlv (found: %d)", tlvType)
		atomic.AddInt64(&s.streams, -1)
		return
	}
	remotePort := binary.BigEndian.Uint16(tcpConnectTLVData[1:3])
	remoteHost := net.IP(tcpConnectTLVData[15:]).String()
	addr := net.JoinHostPort(remoteHost, strconv.Itoa(int(remotePort)))
	tcpConn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Print(fmt.Errorf("net.Dial: %w", err))
		atomic.AddInt64(&s.streams, -1)
		return
	}

	if _, err := stream.Write([]byte{0x01, 0xFF}); err != nil {
		log.Print(fmt.Errorf("stream.Write: %w", err))
		atomic.AddInt64(&s.streams, -1)
		tcpConn.Close()
		return
	}

	utils.Pipe(stream, tcpConn, &s.streams)
}
