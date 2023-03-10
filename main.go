package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"

	"github.com/OmarTariq612/tcp-over-quic/client"
	"github.com/OmarTariq612/tcp-over-quic/server"
)

const (
	keyFile  = "site.key"
	certFile = "site.crt"
)

func main() {
	isServer := flag.Bool("s", false, "server or client mode (client by default)")
	sourceAddr := flag.String("bind", "localhost:5555", "bind address in form (IP:PORT) (quic for server, tcp for client)")
	serverAddr := flag.String("server-addr", "", "server address in form (IP:PORT) (client option only)")
	destAddr := flag.String("dest-addr", "", "final destination address in form (IP:PORT) (client option only)")
	flag.Parse()

	// TODO: handle program arguments better

	if *isServer {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalln(fmt.Errorf("loadX509KeyPair: %w", err))
		}
		s := server.Server{Certificate: cert, QUICSourceAddr: *sourceAddr}
		s.Serve()
	} else {
		if *serverAddr == "" {
			log.Fatalln("serverAddr must be specified in client mode")
		}
		if *destAddr == "" {
			log.Fatalln("destAddr must be specified in client mode")
		}
		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			log.Fatalln(fmt.Errorf("systemCertPool: %w", err))
		}
		c := client.Client{IsInsecure: true, RootCAs: caCertPool, QUICServerAddr: *serverAddr, TCPSourceAddr: *sourceAddr, TCPDestAddr: *destAddr}
		c.Serve()
	}
}
