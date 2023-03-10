package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

type Client struct {
	IsInsecure     bool
	TCPSourceAddr  string
	TCPDestAddr    string
	QUICServerAddr string
	RootCAs        *x509.CertPool
	streams        int64
}

func (c *Client) Serve() {
	http.HandleFunc("/client", func(w http.ResponseWriter, r *http.Request) {
		utils.WriteJSON(w, http.StatusOK, utils.Envelope{"streams": c.streams}, nil)
	})

	go http.ListenAndServe(":7777", nil)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.IsInsecure,
		RootCAs:            c.RootCAs,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{utils.PROTO},
	}

	quicConn, err := quic.DialAddr(c.QUICServerAddr, tlsConfig, &quic.Config{MaxIdleTimeout: 24 * time.Hour})
	if err != nil {
		log.Fatalln(fmt.Errorf("dialAddr: %w", err))
	}

	clientServer, err := net.Listen("tcp", c.TCPSourceAddr)
	if err != nil {
		log.Fatalln(fmt.Errorf("listen: %w", err))
	}

	log.Printf("%s[TCP]%s Listening on %s", utils.GREEN, utils.END, c.TCPSourceAddr)
	log.Printf("%s[QUIC]%s Forwarding to %s", utils.ORANGE, utils.END, c.QUICServerAddr)

	for {
		tcpConn, err := clientServer.Accept()
		if err != nil {
			log.Print(fmt.Errorf("accept: %w", err))
			continue
		}

		go c.handleTCPTunneling(quicConn, tcpConn)
	}
}

func (c *Client) handleTCPTunneling(quicConn quic.Connection, tcpConn net.Conn) {
	stream, err := quicConn.OpenStreamSync(context.Background())
	if err != nil {
		log.Print(fmt.Errorf("openStreamSync: %w", err))
		tcpConn.Close()
		return
	}
	atomic.AddInt64(&c.streams, 1)

	defer func() {
		stream.CancelRead(utils.TCP_CONNECTION_RESET)
		stream.CancelWrite(utils.TCP_CONNECTION_RESET)
		tcpConn.Close()
	}()

	tcpConnectTLVData := make([]byte, 2, 20)
	tcpConnectTLVData[0] = 0x00
	tcpConnectTLVData[1] = 18

	host, portStr, err := net.SplitHostPort(c.TCPDestAddr)
	if err != nil {
		log.Print(fmt.Errorf("net.SplitHostPort: %w", err))
		tcpConn.Close()
		atomic.AddInt64(&c.streams, -1)
		return
	}

	hostBytes := net.ParseIP(host).To4()
	var portBytes [2]byte
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Print(fmt.Errorf("strconv.Atoi: %w", err))
		tcpConn.Close()
		atomic.AddInt64(&c.streams, -1)
		return
	}
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))

	fmt.Println(len(hostBytes))

	tcpConnectTLVData = append(tcpConnectTLVData, portBytes[:]...)
	tcpConnectTLVData = append(tcpConnectTLVData, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF}...)
	tcpConnectTLVData = append(tcpConnectTLVData, hostBytes...)

	fmt.Println(len(tcpConnectTLVData))

	if _, err := stream.Write(tcpConnectTLVData); err != nil {
		log.Print(fmt.Errorf("stream.Write: %w", err))
		tcpConn.Close()
		atomic.AddInt64(&c.streams, -1)
		return
	}

	if _, err := stream.Write([]byte{0xFF}); err != nil {
		log.Print(fmt.Errorf("stream.Write (2): %w", err))
		tcpConn.Close()
		atomic.AddInt64(&c.streams, -1)
		return
	}

	// TODO: look at the received tlvs
	var resp [2]byte
	if _, err := io.ReadFull(stream, resp[:]); err != nil {
		log.Print(fmt.Errorf("io.ReadFull: %w", err))
		tcpConn.Close()
		atomic.AddInt64(&c.streams, -1)
		return
	}

	fmt.Println(resp)

	utils.Pipe(stream, tcpConn, &c.streams)
}
