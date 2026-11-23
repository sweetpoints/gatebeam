// Command backend is an exclusively owned test fixture, never production input.
package main

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	root := os.Args[1]
	if len(os.Args) > 2 && os.Args[2] == "revocation" {
		runRevocation(root)
		return
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" && r.Header.Get("Upgrade") == "websocket" {
			conn, rw, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer conn.Close()
			sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
			rw.Flush()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			frame := make([]byte, 8)
			if _, e := io.ReadFull(rw, frame); e == nil {
				rw.Write([]byte{0x81, 2, frame[6] ^ frame[2], frame[7] ^ frame[3]})
				rw.Flush()
			}
			return
		}
		if r.URL.Path == "/sse" || r.URL.Path == "/sse-buffered" {
			w.Header().Set("Content-Type", "text/event-stream")
			// The standard SSE id carries this owned fixture's emission timestamp,
			// after TLS setup, so the proxy latency probe cannot count handshakes.
			fmt.Fprintf(w, "id: %d\ndata: first\n\n", time.Now().UnixNano())
			if r.URL.Path == "/sse-buffered" {
				// Negative control: even headers are withheld until Flush. A
				// probe timed only after client.Get would falsely accept this.
				time.Sleep(400 * time.Millisecond)
			}
			w.(http.Flusher).Flush()
			time.Sleep(400 * time.Millisecond)
			fmt.Fprint(w, "data: second\n\n")
			return
		}
		if r.URL.Path == "/ordinary429" {
			w.WriteHeader(429)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		sni := ""
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"sni": sni, "host": r.Host, "uri": r.RequestURI, "method": r.Method, "body": string(body), "xff": r.Header.Get("X-Forwarded-For"), "cf": r.Header.Get("CF-Connecting-IP"), "forwarded": r.Header.Get("Forwarded")})
	})
	for i, port := range []string{"9443", "9444"} {
		name := []string{"a", "b"}[i]
		server := &http.Server{TLSConfig: &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			pair, e := tls.LoadX509KeyPair(root+"/"+name+".pem", root+"/"+name+".key")
			return &pair, e
		}}, Addr: ":" + port, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
		go func() {
			if e := server.ListenAndServeTLS("", ""); e != nil {
				panic(e)
			}
		}()
	}
	select {}
}
