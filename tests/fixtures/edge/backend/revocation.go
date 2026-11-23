package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

func runRevocation(root string) {
	var config struct {
		Address string
		Serials map[string]string
	}
	raw, e := os.ReadFile(root + "/revocation.json")
	if e != nil {
		panic(e)
	}
	if e = json.Unmarshal(raw, &config); e != nil {
		panic(e)
	}
	socket, e := net.ListenPacket("udp", ":1053")
	if e != nil {
		panic(e)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, e := socket.ReadFrom(buf)
			if e != nil {
				return
			}
			q := append([]byte{}, buf[:n]...)
			if n < 17 {
				continue
			}
			end := 12
			labels := []string{}
			for end < n && q[end] != 0 {
				size := int(q[end])
				if end+1+size >= n {
					break
				}
				labels = append(labels, string(q[end+1:end+1+size]))
				end += size + 1
			}
			if end+5 > n {
				continue
			}
			end += 5
			name := strings.ToLower(strings.Join(labels, "."))
			reply := append([]byte{}, q[:end]...)
			reply[2] = 0x81
			reply[3] = 0x80
			binary.BigEndian.PutUint16(reply[6:8], 0)
			if name == "ocsp.owned.test" && binary.BigEndian.Uint16(q[end-4:end-2]) == 1 {
				binary.BigEndian.PutUint16(reply[6:8], 1)
				ip := netip.MustParseAddr(config.Address).As4()
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4)
				reply = append(reply, ip[:]...)
				fmt.Println("owned DNS", name)
			} else if name != "ocsp.owned.test" {
				reply[3] = 0x83
			}
			socket.WriteTo(reply, peer)
		}
	}()
	server := &http.Server{Addr: ":9080", ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 8 * time.Second, MaxHeaderBytes: 8192, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ready" {
			w.WriteHeader(204)
			return
		}
		parts := strings.SplitN(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/", 2)
		if len(parts) != 2 {
			http.Error(w, "bad OCSP request", 400)
			return
		}
		kind := parts[0]
		var request []byte
		if r.Method == "POST" {
			request, _ = io.ReadAll(io.LimitReader(r.Body, 4096))
		} else {
			encoded, e := url.PathUnescape(parts[1])
			if e != nil {
				http.Error(w, "bad encoding", 400)
				return
			}
			request, e = base64.StdEncoding.DecodeString(encoded)
			if e != nil {
				http.Error(w, "bad encoding", 400)
				return
			}
		}
		parsed, e := ocsp.ParseRequest(request)
		if e != nil || parsed.SerialNumber.String() != config.Serials[kind] {
			http.Error(w, "unknown request", 400)
			return
		}
		fmt.Println("owned OCSP", kind)
		if kind == "timeout" {
			<-r.Context().Done()
			return
		}
		if kind != "good" && kind != "revoked" && kind != "unknown" {
			http.Error(w, "unknown request", 400)
			return
		}
		response, e := os.ReadFile(root + "/" + kind + ".ocsp")
		if e != nil {
			http.Error(w, "missing response", 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(response)
	})}
	if e := server.ListenAndServe(); e != nil {
		panic(e)
	}
}
