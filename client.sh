#!/bin/bash

QUIC_GO_LOG_LEVEL=INFO ./tcp-over-quic -bind localhost:1111 -dest-addr 127.0.0.1:5555 -server-addr 127.0.0.1:5555
